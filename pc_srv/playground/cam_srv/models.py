from django.db import models
import os

# Create your models here.
class PictureModel(models.Model):
    picture = models.FileField(upload_to = os.path.dirname(__file__))
