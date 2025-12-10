import base64
import importlib
import itertools
import json
import logging
import os
import hmac
import hashlib
import ssl
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

try:
    import bcrypt
except ImportError:
    bcrypt = None

import certifi
import gradio as gr
import httpx

from docling.datamodel.base_models import FormatToExtensions
from docling.datamodel.pipeline_options import (
    PdfBackend,
    ProcessingPipeline,
    TableFormerMode,
    TableStructureOptions,
)

from docling_serve.helper_functions import _to_list_of_strings
from docling_serve.settings import docling_serve_settings, uvicorn_settings

logger = logging.getLogger(__name__)

# Secret key for signing session tokens (use same as DOCLING_SECRET_KEY if set)
SECRET_KEY = os.environ.get("DOCLING_SECRET_KEY", "change-me-session-key").encode()
SESSION_TTL_SECONDS = 120 * 60  # 120 minutes

#########################
# User DB + Auth Utils  #
#########################

USERS_DB = Path(os.environ.get("DOCLING_USERS_PATH", "users.json"))

def load_users():
    if USERS_DB.exists():
        try:
            return json.load(open(USERS_DB))
        except Exception:
            return []
    
    # Auto-create admin user from environment variables if users.json doesn't exist
    username = os.environ.get("DOCLING_UI_USERNAME")
    password = os.environ.get("DOCLING_UI_PASSWORD")
    
    if username and password:
        logger.info(f"Creating initial admin user '{username}' from environment variables")
        admin_user = {
            "username": username,
            "password": hash_password(password),
            "role": "admin"
        }
        try:
            save_users([admin_user])
            logger.info(f"✓ Admin user '{username}' created successfully")
            return [admin_user]
        except Exception as e:
            logger.error(f"Failed to create admin user: {e}")
    
    # No users file and no env vars - return empty list
    return []


def save_users(users):
    json.dump(users, open(USERS_DB, "w"), indent=2)
    # Set restrictive file permissions (readable/writable by owner only)
    try:
        os.chmod(USERS_DB, 0o600)
    except Exception:
        pass


def hash_password(password: str) -> str:
    """Hash a password using bcrypt. Falls back to plaintext if bcrypt unavailable."""
    if bcrypt:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Fallback: plaintext (NOT secure, for dev only)
    logger.warning("bcrypt not available. Using plaintext passwords (INSECURE FOR PRODUCTION).")
    return password


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash using bcrypt. Falls back to plaintext comparison."""
    if bcrypt:
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False
    # Fallback: plaintext comparison
    return password == hashed


def authenticate_user(username, password):
    users = load_users()
    for u in users:
        if u.get("username") == username:
            if verify_password(password, u.get("password", "")):
                return True, u.get("role")
    return False, None


# --- Session token helpers at module level ---
def create_session_token(username: str, role: str) -> str:
    """Create a signed session token with expiry."""
    payload = {
        "u": username,
        "r": role,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    payload_bytes = json.dumps(payload).encode()
    sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload_bytes + b"." + sig).decode()
    return token


def verify_session_token(token: str):
    """Return (username, role) if token is valid and not expired, else (None, None)."""
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        payload_bytes, sig = raw.rsplit(b".", 1)
        expected_sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected_sig):
            return None, None
        payload = json.loads(payload_bytes.decode())
        if payload.get("exp", 0) < int(time.time()):
            return None, None
        return payload.get("u"), payload.get("r")
    except Exception:
        return None, None


def create_user(admin_username, new_username, new_password, new_role):
    users = load_users()

    admin = next((u for u in users if u.get("username") == admin_username), None)
    if not admin or admin.get("role") != "admin":
        return False, "Only admin may create new accounts."

    if any(u.get("username") == new_username for u in users):
        return False, "User already exists."

    # Hash password before storing
    hashed = hash_password(new_password)
    users.append({"username": new_username, "password": hashed, "role": new_role})
    save_users(users)
    return True, "User created successfully."


# --- Auto login handler at module level ---
def auto_login_handler(token: str):
    """Called on page load with the token from cookie. Decides whether to show login or main screen."""
    logger.info(f"Auto-login called with token: {token[:20] if token else 'None'}...")
    
    if not token:
        # No token -> show login screen
        logger.info("No token found, showing login screen")
        return (
            gr.update(visible=True),   # login_screen
            gr.update(visible=False),  # main_screen
            None,                      # session_user
            None,                      # session_role
            gr.update(visible=False, value=""),  # login_error
            gr.update(visible=False),  # admin_panel
            "",                        # session_token component cleared
        )

    username, role = verify_session_token(token)
    if not username:
        # Invalid or expired token -> show login
        logger.info("Token invalid or expired, showing login screen")
        return (
            gr.update(visible=True),
            gr.update(visible=False),
            None,
            None,
            gr.update(visible=False, value=""),  # no error text
            gr.update(visible=False),
            "",  # clear token
        )

    # Valid token -> directly show main screen
    logger.info(f"Valid token for user '{username}', showing main screen")
    return (
        gr.update(visible=False),
        gr.update(visible=True),
        username,
        role,
        gr.update(visible=False, value=""),
        gr.update(visible=(role == "admin")),
        token,
    )


# --- Create user handler at module level ---
def handle_create_user(current_user: str, new_username: str, new_password: str, new_role: str):
    """Create a new user (admin only)."""
    ok, msg = create_user(current_user, new_username, new_password, new_role)
    return msg


# --- Logout handler at module level ---
def logout_handler():
    """Clear session and return to login screen."""
    return (
        gr.update(visible=True),   # login_screen
        gr.update(visible=False),  # main_screen
        None,                      # session_user
        None,                      # session_role
        gr.update(visible=False, value=""),  # login_error
        gr.update(visible=False),  # admin_panel
        "",                        # clear session_token
    )


# Login handler for Gradio UI
def login_handler(username: str, password: str):
    ok, role = authenticate_user(username, password)
    if ok:
        token = create_session_token(username, role)
        # hide login screen, show main screen, set session states, clear error
        # admin_panel visible only for admin users
        return (
            gr.update(visible=False),  # login_screen
            gr.update(visible=True),   # main_screen
            username,                  # session_user
            role,                      # session_role
            gr.update(visible=False, value=""),  # login_error
            gr.update(visible=(role == "admin")),  # admin_panel
            token,                     # session_token (hidden component)
        )
    else:
        # show error message, hide main screen and admin panel
        return (
            gr.update(visible=True),   # login_screen
            gr.update(visible=False),  # main_screen
            None,                      # session_user
            None,                      # session_role
            gr.update(visible=True, value="Invalid username or password."),  # login_error
            gr.update(visible=False),  # admin_panel
            "",                        # clear token
        )


############################
# Path of static artifacts #
############################

logo_path = "https://raw.githubusercontent.com/docling-project/docling/refs/heads/main/docs/assets/logo.svg"
js_components_url = "https://unpkg.com/@docling/docling-components@0.0.7"
if (
    docling_serve_settings.static_path is not None
    and docling_serve_settings.static_path.is_dir()
):
    logo_path = str(docling_serve_settings.static_path / "logo.svg")
    js_components_url = "/static/docling-components.js"


##############################
# Head JS for web components #
##############################
head = f"""
    <script src="{js_components_url}" type="module"></script>
"""

#################
# CSS and theme #
#################

css = """
#logo {
    border-style: none;
    background: none;
    box-shadow: none;
    min-width: 80px;
}
#dark_mode_column {
    display: flex;
    align-content: flex-end;
}
#title {
    text-align: left;
    display:block;
    height: auto;
    padding-top: 5px;
    line-height: 0;
}
.title-text h1 > p, .title-text p {
    margin-top: 0px !important;
    margin-bottom: 2px !important;
}
#custom-container {
    border: 0.909091px solid;
    padding: 10px;
    border-radius: 4px;
}
#custom-container h4 {
    font-size: 14px;
}
#file_input_zone {
    height: 140px;
}
#user_info_column {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
}
#user_name_text {
    font-size: 18px;
    font-weight: 600;
    margin: 0;
}
#logout_btn {
    max-width: 100px;
}

docling-img {
    gap: 1rem;
}

docling-img::part(page) {
    box-shadow: 0 0.5rem 1rem 0 rgba(0, 0, 0, 0.2);
}
"""

theme = gr.themes.Default(
    text_size="md",
    spacing_size="md",
    font=[
        gr.themes.GoogleFont("Red Hat Display"),
        "ui-sans-serif",
        "system-ui",
        "sans-serif",
    ],
    font_mono=[
        gr.themes.GoogleFont("Red Hat Mono"),
        "ui-monospace",
        "Consolas",
        "monospace",
    ],
)

#############
# Variables #
#############

gradio_output_dir = None  # Will be set by FastAPI when mounted
file_output_path = None  # Will be set when a new file is generated

#############
# Functions #
#############


def get_api_endpoint() -> str:
    protocol = "http"
    if uvicorn_settings.ssl_keyfile is not None:
        protocol = "https"
    return f"{protocol}://{docling_serve_settings.api_host}:{uvicorn_settings.port}"


def get_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=certifi.where())
    kube_sa_ca_cert_path = Path(
        "/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
    )
    if (
        uvicorn_settings.ssl_keyfile is not None
        and ".svc." in docling_serve_settings.api_host
        and kube_sa_ca_cert_path.exists()
    ):
        ctx.load_verify_locations(cafile=kube_sa_ca_cert_path)
    return ctx


def health_check():
    response = httpx.get(f"{get_api_endpoint()}/health")
    if response.status_code == 200:
        return "Healthy"
    return "Unhealthy"


def set_options_visibility(x):
    return gr.Accordion("Options", open=x)


def set_outputs_visibility_direct(x, y):
    content = gr.Row(visible=x)
    file = gr.Row(visible=y)
    return content, file


def set_task_id_visibility(x):
    task_id_row = gr.Row(visible=x)
    return task_id_row


def set_outputs_visibility_process(x):
    content = gr.Row(visible=not x)
    file = gr.Row(visible=x)
    return content, file


def set_download_button_label(label_text: gr.State):
    return gr.DownloadButton(label=str(label_text), scale=1)


def clear_outputs():
    task_id_rendered = ""
    markdown_content = ""
    json_content = ""
    json_rendered_content = ""
    html_content = ""
    text_content = ""
    doctags_content = ""

    return (
        task_id_rendered,
        markdown_content,
        markdown_content,
        json_content,
        json_rendered_content,
        html_content,
        html_content,
        text_content,
        doctags_content,
    )


def clear_url_input():
    return ""


def clear_file_input():
    return None


def auto_set_return_as_file(
    url_input_value: str,
    file_input_value: Optional[list[str]],
    image_export_mode_value: str,
):
    # If more than one input source is provided, return as file
    if (
        (len(url_input_value.split(",")) > 1)
        or (file_input_value and len(file_input_value) > 1)
        or (image_export_mode_value == "referenced")
    ):
        return True
    else:
        return False


def change_ocr_lang(ocr_engine):
    if ocr_engine == "easyocr":
        return gr.update(visible=True, value="en,fr,de,es")
    elif ocr_engine == "tesseract_cli":
        return gr.update(visible=True, value="eng,fra,deu,spa")
    elif ocr_engine == "tesseract":
        return gr.update(visible=True, value="eng,fra,deu,spa")
    elif ocr_engine == "rapidocr":
        return gr.update(visible=True, value="english,chinese")
    elif ocr_engine == "ocrmac":
        return gr.update(visible=True, value="fr-FR,de-DE,es-ES,en-US")

    return gr.update(visible=False, value="")


def wait_task_finish(auth: str, task_id: str, return_as_file: bool):
    conversion_sucess = False
    task_finished = False
    task_status = ""

    headers = {}
    if docling_serve_settings.api_key:
        headers["X-Api-Key"] = str(auth)

    ssl_ctx = get_ssl_context()
    while not task_finished:
        try:
            response = httpx.get(
                f"{get_api_endpoint()}/v1/status/poll/{task_id}?wait=5",
                headers=headers,
                verify=ssl_ctx,
                timeout=15,
            )
            task_status = response.json()["task_status"]
            if task_status == "success":
                conversion_sucess = True
                task_finished = True

            if task_status in ("failure", "revoked"):
                conversion_sucess = False
                task_finished = True
                raise RuntimeError(f"Task failed with status {task_status!r}")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error processing file(s): {e}")
            conversion_sucess = False
            task_finished = True
            raise gr.Error(f"Error processing file(s): {e}", print_exception=False)

    if conversion_sucess:
        try:
            response = httpx.get(
                f"{get_api_endpoint()}/v1/result/{task_id}",
                headers=headers,
                timeout=15,
                verify=ssl_ctx,
            )
            output = response_to_output(response, return_as_file)
            return output
        except Exception as e:
            logger.error(f"Error getting task result: {e}")

    raise gr.Error(
        f"Error getting task result, conversion finished with status: {task_status}"
    )


def process_url(
    auth,
    input_sources,
    to_formats,
    image_export_mode,
    pipeline,
    ocr,
    force_ocr,
    ocr_engine,
    ocr_lang,
    pdf_backend,
    table_mode,
    abort_on_error,
    return_as_file,
    do_code_enrichment,
    do_formula_enrichment,
    do_picture_classification,
    do_picture_description,
):
    target = {"kind": "zip" if return_as_file else "inbody"}
    parameters = {
        "sources": [
            {"kind": "http", "url": source} for source in input_sources.split(",")
        ],
        "options": {
            "to_formats": to_formats,
            "image_export_mode": image_export_mode,
            "pipeline": pipeline,
            "ocr": ocr,
            "force_ocr": force_ocr,
            "ocr_engine": ocr_engine,
            "ocr_lang": _to_list_of_strings(ocr_lang),
            "pdf_backend": pdf_backend,
            "table_mode": table_mode,
            "abort_on_error": abort_on_error,
            "do_code_enrichment": do_code_enrichment,
            "do_formula_enrichment": do_formula_enrichment,
            "do_picture_classification": do_picture_classification,
            "do_picture_description": do_picture_description,
        },
        "target": target,
    }
    if (
        not parameters["sources"]
        or len(parameters["sources"]) == 0
        or parameters["sources"][0]["url"] == ""
    ):
        logger.error("No input sources provided.")
        raise gr.Error("No input sources provided.", print_exception=False)

    headers = {}
    if docling_serve_settings.api_key:
        headers["X-Api-Key"] = str(auth)

    print(f"{headers=}")
    try:
        ssl_ctx = get_ssl_context()
        response = httpx.post(
            f"{get_api_endpoint()}/v1/convert/source/async",
            json=parameters,
            headers=headers,
            verify=ssl_ctx,
            timeout=60,
        )
    except Exception as e:
        logger.error(f"Error processing URL: {e}")
        raise gr.Error(f"Error processing URL: {e}", print_exception=False)
    if response.status_code != 200:
        data = response.json()
        error_message = data.get("detail", "An unknown error occurred.")
        logger.error(f"Error processing file: {error_message}")
        raise gr.Error(f"Error processing file: {error_message}", print_exception=False)

    task_id_rendered = response.json()["task_id"]
    return task_id_rendered


def file_to_base64(file):
    with open(file.name, "rb") as f:
        encoded_string = base64.b64encode(f.read()).decode("utf-8")
    return encoded_string


def process_file(
    auth,
    files,
    to_formats,
    image_export_mode,
    pipeline,
    ocr,
    force_ocr,
    ocr_engine,
    ocr_lang,
    pdf_backend,
    table_mode,
    abort_on_error,
    return_as_file,
    do_code_enrichment,
    do_formula_enrichment,
    do_picture_classification,
    do_picture_description,
):
    if not files or len(files) == 0:
        logger.error("No files provided.")
        raise gr.Error("No files provided.", print_exception=False)
    files_data = [
        {"kind": "file", "base64_string": file_to_base64(file), "filename": file.name}
        for file in files
    ]
    target = {"kind": "zip" if return_as_file else "inbody"}

    parameters = {
        "sources": files_data,
        "options": {
            "to_formats": to_formats,
            "image_export_mode": image_export_mode,
            "pipeline": pipeline,
            "ocr": ocr,
            "force_ocr": force_ocr,
            "ocr_engine": ocr_engine,
            "ocr_lang": _to_list_of_strings(ocr_lang),
            "pdf_backend": pdf_backend,
            "table_mode": table_mode,
            "abort_on_error": abort_on_error,
            "return_as_file": return_as_file,
            "do_code_enrichment": do_code_enrichment,
            "do_formula_enrichment": do_formula_enrichment,
            "do_picture_classification": do_picture_classification,
            "do_picture_description": do_picture_description,
        },
        "target": target,
    }

    headers = {}
    if docling_serve_settings.api_key:
        headers["X-Api-Key"] = str(auth)

    try:
        ssl_ctx = get_ssl_context()
        response = httpx.post(
            f"{get_api_endpoint()}/v1/convert/source/async",
            json=parameters,
            headers=headers,
            verify=ssl_ctx,
            timeout=60,
        )
    except Exception as e:
        logger.error(f"Error processing file(s): {e}")
        raise gr.Error(f"Error processing file(s): {e}", print_exception=False)
    if response.status_code != 200:
        data = response.json()
        error_message = data.get("detail", "An unknown error occurred.")
        logger.error(f"Error processing file: {error_message}")
        raise gr.Error(f"Error processing file: {error_message}", print_exception=False)

    task_id_rendered = response.json()["task_id"]
    return task_id_rendered


def response_to_output(response, return_as_file):
    markdown_content = ""
    json_content = ""
    json_rendered_content = ""
    html_content = ""
    text_content = ""
    doctags_content = ""
    download_button = gr.DownloadButton(visible=False, label="Download Output", scale=1)
    if return_as_file:
        filename = (
            response.headers.get("Content-Disposition").split("filename=")[1].strip('"')
        )
        tmp_output_dir = Path(tempfile.mkdtemp(dir=gradio_output_dir, prefix="ui_"))
        file_output_path = f"{tmp_output_dir}/{filename}"
        # logger.info(f"Saving file to: {file_output_path}")
        with open(file_output_path, "wb") as f:
            f.write(response.content)
        download_button = gr.DownloadButton(
            visible=True, label=f"Download {filename}", scale=1, value=file_output_path
        )
    else:
        full_content = response.json()
        markdown_content = full_content.get("document").get("md_content")
        json_content = json.dumps(
            full_content.get("document").get("json_content"), indent=2
        )
        # Embed document JSON and trigger load at client via an image.
        json_rendered_content = f"""
            <docling-img id="dclimg" pagenumbers><docling-tooltip></docling-tooltip></docling-img>
            <script id="dcljson" type="application/json" onload="document.getElementById('dclimg').src = JSON.parse(document.getElementById('dcljson').textContent);">{json_content}</script>
            <img src onerror="document.getElementById('dclimg').src = JSON.parse(document.getElementById('dcljson').textContent);" />
            """
        html_content = full_content.get("document").get("html_content")
        text_content = full_content.get("document").get("text_content")
        doctags_content = full_content.get("document").get("doctags_content")
    return (
        markdown_content,
        markdown_content,
        json_content,
        json_rendered_content,
        html_content,
        html_content,
        text_content,
        doctags_content,
        download_button,
    )


############
# UI Setup #
############

with gr.Blocks(
    head=head,
    css=css,
    theme=theme,
    title="Docling Serve",
    delete_cache=(3600, 36000),  # Delete all files older than 10 hour every hour
) as ui:
    # Constants stored in states to be able to pass them as inputs to functions
    processing_text = gr.State("Processing your document(s), please wait...")
    true_bool = gr.State(True)
    false_bool = gr.State(False)

    # Session states for login
    session_user = gr.State(None)
    session_role = gr.State(None)

    # Hidden component to store session token (synced with cookie)
    session_token = gr.Textbox(visible=False)

    ######################################
    # Login Screen (FIRST SCREEN)        #
    ######################################

    with gr.Column(visible=True) as login_screen:
        gr.Markdown("## 🔐 Login to Docling Portal")

        login_username = gr.Textbox(label="Username")
        login_password = gr.Textbox(label="Password", type="password")

        login_button = gr.Button("Login")
        login_error = gr.Markdown(visible=False)

    ######################################
    # Main UI Screen (Hidden Until Login)#
    ######################################

    # Use a Column for the main screen so content flows vertically
    with gr.Column(visible=False) as main_screen:

        # Banner
        with gr.Row(elem_id="check_health"):
            # Logo
            with gr.Column(scale=1, min_width=90):
                try:
                    gr.Image(
                        logo_path,
                        height=80,
                        width=80,
                        show_download_button=False,
                        show_label=False,
                        show_fullscreen_button=False,
                        container=False,
                        elem_id="logo",
                        scale=0,
                    )
                except Exception:
                    logger.warning("Logo not found.")

            # Title
            with gr.Column(scale=1, min_width=200):
                gr.Markdown(
                    f"# Docling Serve \n(docling version: "
                    f"{importlib.metadata.version('docling')})",
                    elem_id="title",
                    elem_classes=["title-text"],
                )
            
            # User info and logout button (top-right)
            with gr.Column(scale=16, elem_id="user_info_column"):
                with gr.Row():
                    user_name_display = gr.Markdown("", elem_id="user_name_text")
                    logout_btn = gr.Button("Logout", elem_id="logout_btn", scale=0)
            
            # Dark mode button
            with gr.Column(scale=16, elem_id="dark_mode_column"):
                dark_mode_btn = gr.Button("Dark/Light Mode", scale=0)
                dark_mode_btn.click(
                    None,
                    None,
                    None,
                    js="""() => {
                        if (document.querySelectorAll('.dark').length) {
                            document.querySelectorAll('.dark').forEach(
                            el => el.classList.remove('dark')
                            );
                        } else {
                            document.querySelector('body').classList.add('dark');
                        }
                    }""",
                    show_api=False,
                )

        # URL Processing Tab
        with gr.Tab("Convert URL"):
            with gr.Row():
                with gr.Column(scale=4):
                    url_input = gr.Textbox(
                        label="URL Input Source",
                        placeholder="https://arxiv.org/pdf/2501.17887",
                    )
                with gr.Column(scale=1):
                    url_process_btn = gr.Button("Process URL", scale=1)
                    url_reset_btn = gr.Button("Reset", scale=1)

        # File Processing Tab
        with gr.Tab("Convert File"):
            with gr.Row():
                with gr.Column(scale=4):
                    raw_exts = itertools.chain.from_iterable(FormatToExtensions.values())
                    file_input = gr.File(
                        elem_id="file_input_zone",
                        label="Upload File",
                        file_types=[
                            f".{v.lower()}"
                            for v in raw_exts  # lowercase
                        ]
                        + [
                            f".{v.upper()}"
                            for v in raw_exts  # uppercase
                        ],
                        file_count="multiple",
                        scale=4,
                    )
                with gr.Column(scale=1):
                    file_process_btn = gr.Button("Process File", scale=1)
                    file_reset_btn = gr.Button("Reset", scale=1)

        # Auth
        with gr.Row(visible=bool(docling_serve_settings.api_key)):
            with gr.Column():
                auth = gr.Textbox(
                    label="Authentication",
                    placeholder="API Key",
                    type="password",
                )

        # Options
        with gr.Accordion("Options") as options:
            with gr.Row():
                with gr.Column(scale=1):
                    to_formats = gr.CheckboxGroup(
                        [
                            ("Docling (JSON)", "json"),
                            ("Markdown", "md"),
                            ("HTML", "html"),
                            ("Plain Text", "text"),
                            ("Doc Tags", "doctags"),
                        ],
                        label="To Formats",
                        value=["json", "md"],
                    )
                with gr.Column(scale=1):
                    image_export_mode = gr.Radio(
                        [
                            ("Embedded", "embedded"),
                            ("Placeholder", "placeholder"),
                            ("Referenced", "referenced"),
                        ],
                        label="Image Export Mode",
                        value="embedded",
                    )

            with gr.Row():
                with gr.Column(scale=1, min_width=200):
                    pipeline = gr.Radio(
                        [(v.value.capitalize(), v.value) for v in ProcessingPipeline],
                        label="Pipeline type",
                        value=ProcessingPipeline.STANDARD.value,
                    )
            with gr.Row():
                with gr.Column(scale=1, min_width=200):
                    ocr = gr.Checkbox(label="Enable OCR", value=True)
                    force_ocr = gr.Checkbox(label="Force OCR", value=False)
                with gr.Column(scale=1):
                    engines_list = [
                        ("Auto", "auto"),
                        ("EasyOCR", "easyocr"),
                        ("Tesseract", "tesseract"),
                        ("RapidOCR", "rapidocr"),
                    ]
                    if sys.platform == "darwin":
                        engines_list.append(("OCRMac", "ocrmac"))

                    ocr_engine = gr.Radio(
                        engines_list,
                        label="OCR Engine",
                        value="auto",
                    )
                with gr.Column(scale=1, min_width=200):
                    ocr_lang = gr.Textbox(
                        label="OCR Language (beware of the format)",
                        value="en,fr,de,es",
                        visible=False,
                    )
                ocr_engine.change(change_ocr_lang, inputs=[ocr_engine], outputs=[ocr_lang])
            with gr.Row():
                with gr.Column(scale=4):
                    pdf_backend = gr.Radio(
                        [v.value for v in PdfBackend],
                        label="PDF Backend",
                        value=PdfBackend.DLPARSE_V4.value,
                    )
                with gr.Column(scale=2):
                    table_mode = gr.Radio(
                        [(v.value.capitalize(), v.value) for v in TableFormerMode],
                        label="Table Mode",
                        value=TableStructureOptions().mode.value,
                    )
                with gr.Column(scale=1):
                    abort_on_error = gr.Checkbox(label="Abort on Error", value=False)
                    return_as_file = gr.Checkbox(label="Return as File", value=False)
            with gr.Row():
                with gr.Column():
                    do_code_enrichment = gr.Checkbox(
                        label="Enable code enrichment", value=False
                    )
                    do_formula_enrichment = gr.Checkbox(
                        label="Enable formula enrichment", value=False
                    )
                with gr.Column():
                    do_picture_classification = gr.Checkbox(
                        label="Enable picture classification", value=False
                    )
                    do_picture_description = gr.Checkbox(
                        label="Enable picture description", value=False
                    )

        # Task id output
        with gr.Row(visible=False) as task_id_output:
            task_id_rendered = gr.Textbox(label="Task id", interactive=False)

        # Document output
        with gr.Row(visible=False) as content_output:
            with gr.Tab("Docling (JSON)"):
                output_json = gr.Code(language="json", wrap_lines=True, show_label=False)
            with gr.Tab("Docling-Rendered"):
                output_json_rendered = gr.HTML(label="Response")
            with gr.Tab("Markdown"):
                output_markdown = gr.Code(
                    language="markdown", wrap_lines=True, show_label=False
                )
            with gr.Tab("Markdown-Rendered"):
                output_markdown_rendered = gr.Markdown(label="Response")
            with gr.Tab("HTML"):
                output_html = gr.Code(language="html", wrap_lines=True, show_label=False)
            with gr.Tab("HTML-Rendered"):
                output_html_rendered = gr.HTML(label="Response")
            with gr.Tab("Text"):
                output_text = gr.Code(wrap_lines=True, show_label=False)
            with gr.Tab("DocTags"):
                output_doctags = gr.Code(wrap_lines=True, show_label=False)

        # File download output
        with gr.Row(visible=False) as file_output:
            download_file_btn = gr.DownloadButton(label="Placeholder", scale=1)

        ################################
        # Admin Panel (for admins only) #
        ################################

        with gr.Accordion("👑 Admin Panel", visible=False) as admin_panel:
            gr.Markdown("### Create New User")

            new_username = gr.Textbox(label="New Username")
            new_password = gr.Textbox(label="New Password", type="password")
            new_role = gr.Radio(["admin", "user"], label="Role", value="user")

            create_user_button = gr.Button("Create User")
            create_user_result = gr.Markdown()

        ##############
        # UI Actions #
        ##############

        # Handle Return as File
        url_input.change(
            auto_set_return_as_file,
            inputs=[url_input, file_input, image_export_mode],
            outputs=[return_as_file],
        )
        file_input.change(
            auto_set_return_as_file,
            inputs=[url_input, file_input, image_export_mode],
            outputs=[return_as_file],
        )
        image_export_mode.change(
            auto_set_return_as_file,
            inputs=[url_input, file_input, image_export_mode],
            outputs=[return_as_file],
        )

        # URL processing
        url_process_btn.click(
                set_options_visibility, inputs=[false_bool], outputs=[options]
            ).then(
                set_download_button_label, inputs=[processing_text], outputs=[download_file_btn]
            ).then(
                clear_outputs,
                inputs=None,
                outputs=[
                    task_id_rendered,
                    output_markdown,
                    output_markdown_rendered,
                    output_json,
                    output_json_rendered,
                    output_html,
                    output_html_rendered,
                    output_text,
                    output_doctags,
                ],
            ).then(
                set_task_id_visibility,
                inputs=[true_bool],
                outputs=[task_id_output],
            ).then(
                process_url,
                inputs=[
                    auth,
                    url_input,
                    to_formats,
                    image_export_mode,
                    pipeline,
                    ocr,
                    force_ocr,
                    ocr_engine,
                    ocr_lang,
                    pdf_backend,
                    table_mode,
                    abort_on_error,
                    return_as_file,
                    do_code_enrichment,
                    do_formula_enrichment,
                    do_picture_classification,
                    do_picture_description,
                ],
                outputs=[
                    task_id_rendered,
                ],
            ).then(
                set_outputs_visibility_process,
                inputs=[return_as_file],
                outputs=[content_output, file_output],
            ).then(
                wait_task_finish,
                inputs=[auth, task_id_rendered, return_as_file],
                outputs=[
                    output_markdown,
                    output_markdown_rendered,
                    output_json,
                    output_json_rendered,
                    output_html,
                    output_html_rendered,
                    output_text,
                    output_doctags,
                    download_file_btn,
                ],
            )

        url_reset_btn.click(
            clear_outputs,
            inputs=None,
            outputs=[
                output_markdown,
                output_markdown_rendered,
                output_json,
                output_json_rendered,
                output_html,
                output_html_rendered,
                output_text,
                output_doctags,
            ],
        ).then(set_options_visibility, inputs=[true_bool], outputs=[options]).then(
            set_outputs_visibility_direct,
            inputs=[false_bool, false_bool],
            outputs=[content_output, file_output],
        ).then(set_task_id_visibility, inputs=[false_bool], outputs=[task_id_output]).then(
            clear_url_input, inputs=None, outputs=[url_input]
        )

        # File processing
        file_process_btn.click(
            set_options_visibility, inputs=[false_bool], outputs=[options]
        ).then(
            set_download_button_label, inputs=[processing_text], outputs=[download_file_btn]
        ).then(
            clear_outputs,
            inputs=None,
            outputs=[
                task_id_rendered,
                output_markdown,
                output_markdown_rendered,
                output_json,
                output_json_rendered,
                output_html,
                output_html_rendered,
                output_text,
                output_doctags,
            ],
        ).then(
            set_task_id_visibility,
            inputs=[true_bool],
            outputs=[task_id_output],
        ).then(
                process_file,
                inputs=[
                    auth,
                    file_input,
                    to_formats,
                    image_export_mode,
                    pipeline,
                    ocr,
                    force_ocr,
                    ocr_engine,
                    ocr_lang,
                    pdf_backend,
                    table_mode,
                    abort_on_error,
                    return_as_file,
                    do_code_enrichment,
                    do_formula_enrichment,
                    do_picture_classification,
                    do_picture_description,
                ],
                outputs=[
                    task_id_rendered,
                ],
            ).then(
                set_outputs_visibility_process,
                inputs=[return_as_file],
                outputs=[content_output, file_output],
            ).then(
                wait_task_finish,
                inputs=[auth, task_id_rendered, return_as_file],
                outputs=[
                    output_markdown,
                    output_markdown_rendered,
                    output_json,
                    output_json_rendered,
                    output_html,
                    output_html_rendered,
                    output_text,
                    output_doctags,
                    download_file_btn,
                ],
            )

        file_reset_btn.click(
            clear_outputs,
            inputs=None,
            outputs=[
                output_markdown,
                output_markdown_rendered,
                output_json,
                output_json_rendered,
                output_html,
                output_html_rendered,
                output_text,
                output_doctags,
            ],
        ).then(set_options_visibility, inputs=[true_bool], outputs=[options]).then(
            set_outputs_visibility_direct,
            inputs=[false_bool, false_bool],
            outputs=[content_output, file_output],
        ).then(set_task_id_visibility, inputs=[false_bool], outputs=[task_id_output]).then(
            clear_file_input, inputs=None, outputs=[file_input]
        )

    ######################################
    # Wire login + admin create user     #
    ######################################

    # Login button: server-side handler + token
    login_button.click(
        login_handler,
        inputs=[login_username, login_password],
        outputs=[
            login_screen,
            main_screen,
            session_user,
            session_role,
            login_error,
            admin_panel,
            session_token,   # NEW
        ],
    ).then(
        # Update username display after successful login
        lambda username: f"👤 {username}" if username else "",
        inputs=[session_user],
        outputs=[user_name_display],
    )

    # Logout button: clear session and return to login
    logout_btn.click(
        logout_handler,
        inputs=None,
        outputs=[
            login_screen,
            main_screen,
            session_user,
            session_role,
            login_error,
            admin_panel,
            session_token,
        ],
    ).then(
        # Clear username display
        lambda: "",
        inputs=None,
        outputs=[user_name_display],
    )

    # When session_token changes, store it in a cookie for 120 minutes
    session_token.change(
        None,
        inputs=[session_token],
        outputs=None,
        js="""
        (token) => {
            if (!token) {
                // clear cookie
                document.cookie = 'dl_session=; Max-Age=0; path=/; SameSite=Lax';
                return;
            }
            const ttlMinutes = 120;
            const expires = new Date(Date.now() + ttlMinutes * 60 * 1000).toUTCString();
            document.cookie = `dl_session=${encodeURIComponent(token)}; expires=${expires}; path=/; SameSite=Lax`;
            console.log('Cookie set:', document.cookie);
        }
        """,
    )

    # On page load, try to auto-login using the cookie value
    ui.load(
        auto_login_handler,
        inputs=[session_token],
        outputs=[
            login_screen,
            main_screen,
            session_user,
            session_role,
            login_error,
            admin_panel,
            session_token,
        ],
        # JS reads the 'dl_session' cookie and passes it as the input token
        js="""
        () => {
            const match = document.cookie.match(/(?:^|; )dl_session=([^;]+)/);
            return match ? decodeURIComponent(match[1]) : "";
        }
        """,
    ).then(
        # Update username display based on session_user
        lambda username: f"👤 {username}" if username else "",
        inputs=[session_user],
        outputs=[user_name_display],
    )

    # Create user (admin only)
    create_user_button.click(
        handle_create_user,
        inputs=[session_user, new_username, new_password, new_role],
        outputs=[create_user_result],
    )
