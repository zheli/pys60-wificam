from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('',
        url(r'^$', 'data_log.views.index'),
)
