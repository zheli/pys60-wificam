from django.shortcuts import render_to_response
import logging
# Create your views here.
def index(request):
    logging.debug('index page')
    return render_to_response('data_log/index.html', {})
