from django.conf.urls.defaults import patterns, include, url
from piston.resource import Resource
from api.handlers import PictureHandler

picture_handler = Resource(PictureHandler)

urlpatterns = patterns('',
        url(r'^$', picture_handler),
)
