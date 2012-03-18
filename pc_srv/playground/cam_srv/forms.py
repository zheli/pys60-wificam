from cam_srv.models import PictureModel
from django.forms import ModelForm
import os

class UploadFileForm(ModelForm):
    class Meta:
        model = PictureModel

