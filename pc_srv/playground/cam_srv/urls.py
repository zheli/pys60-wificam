from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('',
        url(r'^$', 'cam_srv.views.index'),
        url(r'^upload/$', 'cam_srv.views.upload_file'),
)
