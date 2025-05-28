from django import forms
from ckeditor_uploader.fields import RichTextUploadingFormField

class CkEditorForm(forms.Form):
    ckeditor_upload_example = RichTextUploadingFormField(
        config_name="my-custom-toolbar", extra_plugins=["html5"]
    )
