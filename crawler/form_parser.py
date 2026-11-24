from bs4 import BeautifulSoup
from urllib.parse import urljoin


def parse_forms(url, html_content):
    """
    Extract all forms from a page
    Returns list of form details
    """
    forms = []

    try:
        soup = BeautifulSoup(html_content, "lxml")
        all_forms = soup.find_all("form")

        for form in all_forms:
            form_data = {}

            # Get form action URL and strip fragment
            action = form.attrs.get("action", "").strip()
            if action and not action.startswith("#"):
                clean_action = urljoin(url, action).split("#")[0]
            else:
                clean_action = url.split("#")[0]
            form_data["action"] = clean_action

            # Get form method (default GET)
            method = form.attrs.get("method", "get").strip().lower()
            form_data["method"] = method

            # Get all input fields
            inputs = []
            seen_names = set()

            # Find all input tags
            for input_tag in form.find_all("input"):
                name = input_tag.attrs.get("name", "").strip()
                if not name:
                    # Fallback to id if name is missing
                    name = input_tag.attrs.get("id", "").strip()

                input_type = input_tag.attrs.get("type", "text").strip().lower()
                if input_type in ["submit", "image", "button", "reset"] and not name:
                    continue

                if name and name not in seen_names:
                    seen_names.add(name)
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": input_tag.attrs.get("value", ""),
                        "placeholder": input_tag.attrs.get("placeholder", ""),
                    })

            # Find all textarea tags
            for textarea in form.find_all("textarea"):
                name = textarea.attrs.get("name", "").strip() or textarea.attrs.get("id", "").strip()
                if name and name not in seen_names:
                    seen_names.add(name)
                    inputs.append({
                        "name": name,
                        "type": "textarea",
                        "value": textarea.text.strip(),
                        "placeholder": textarea.attrs.get("placeholder", ""),
                    })

            # Find all select tags
            for select in form.find_all("select"):
                name = select.attrs.get("name", "").strip() or select.attrs.get("id", "").strip()
                if name and name not in seen_names:
                    seen_names.add(name)
                    # Grab default selected value if present
                    selected_opt = select.find("option", selected=True) or select.find("option")
                    opt_val = selected_opt.attrs.get("value", selected_opt.text.strip()) if selected_opt else ""
                    inputs.append({
                        "name": name,
                        "type": "select",
                        "value": opt_val,
                        "placeholder": "",
                    })

            # Find submit buttons with names
            for button in form.find_all("button"):
                name = button.attrs.get("name", "").strip()
                if name and name not in seen_names:
                    seen_names.add(name)
                    inputs.append({
                        "name": name,
                        "type": "submit",
                        "value": button.attrs.get("value", "submit"),
                        "placeholder": "",
                    })

            form_data["inputs"] = inputs
            form_data["source_url"] = url

            # Only add forms that have inputs
            if inputs:
                forms.append(form_data)

    except Exception:
        pass

    return forms


def get_form_summary(forms):
    """
    Print summary of all forms found
    """
    summary = []
    for i, form in enumerate(forms):
        summary.append({
            "form_number": i + 1,
            "action": form["action"],
            "method": form["method"].upper(),
            "input_count": len(form["inputs"]),
            "inputs": [inp["name"] for inp in form["inputs"]],
        })
    return summary
