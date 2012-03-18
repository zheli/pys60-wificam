from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from cam_srv.forms import UploadFileForm
import logging

# Create your views here.
@login_required
def index(request):
    logging.debug('This is index')
    template = 'cam/index.html'
    values = {}
    return render_to_response(template, values)

def upload_file(request):
    if request.method == 'POST':
        logging.debug('Receving POST data...')
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('http://www.google.com')
        else:
            logging.debug('Form invalid')
    else:
        form = UploadFileForm()
        return render_to_response('upload.html', 
                {'form': form},
                context_instance=RequestContext(request))
