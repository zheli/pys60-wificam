from settings import PROJECT_ROOT
from piston.handler import BaseHandler
from piston.utils import rc, validate
from cam_srv.models import PictureModel
import os
import logging

class PictureHandler(BaseHandler):
    model = PictureModel
    allowed_methods = ('POST')

    def create(self, request):
        logging.debug('new POST request')
        handle_uploaded_file(request.FILES['file'])
        return rc.ALL_OK

def handle_uploaded_file(f):
    logging.debug('handle uploaded file')
    file_path = os.path.join(os.path.dirname(__file__), f.name)
    file_path = os.path.join(PROJECT_ROOT, 'uploaded', f.name)
    logging.debug("Save file %s" % file_path)
    destination = open(file_path, 'wb+')
    for chunk in f.chunks():
        destination.write(chunk)
    destination.close()
