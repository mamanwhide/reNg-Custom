from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path, re_path
from django.views.generic.base import RedirectView
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from paraKang.views import serve_protected_media

schema_view = get_schema_view(
   openapi.Info(
      title="paraKang API",
      default_version='v1',
      description="paraKang: An Automated AS framework.",
      contact=openapi.Contact(email="yogesh.ojha11@gmail.com"),
   ),
   public=True,
   permission_classes=[permissions.IsAuthenticated],
)

urlpatterns = [
    path('favicon.ico', RedirectView.as_view(url='/staticfiles/img/favicon.png', permanent=True), name='favicon'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path(
        'admin/',
        admin.site.urls),
    path(
        '',
        include('dashboard.urls')),
    path(
        'target/',
        include('targetApp.urls')),
    path(
        'scanEngine/',
        include('scanEngine.urls')),
    path(
        'scan/',
        include('startScan.urls')),
    path(
        'recon_note/',
        include('recon_note.urls')),
    path(
        'login/',
        auth_views.LoginView.as_view(template_name='base/login.html'),
        name='login'),
    path(
        'logout/',
        auth_views.LogoutView.as_view(template_name='base/logout.html'),
        name='logout'),
    path(
        'api/',
        include(
            'api.urls',
            'api')),
    path(
        'media/<path:path>', 
        serve_protected_media, 
        name='serve_protected_media'
    ),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
# ] + static(settings.MEDIA_URL, document_root=settings.PARAKANG_RESULTS) + \
    
