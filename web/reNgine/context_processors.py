import logging

from dashboard.models import *
from django.conf import settings

logger = logging.getLogger(__name__)


def projects(request):
    projects = Project.objects.all()
    project = None
    try:
        slug = request.resolver_match.kwargs.get('slug') if request.resolver_match else None
        if slug:
            project = Project.objects.get(slug=slug)
    except (Project.DoesNotExist, AttributeError):
        # MED-07 fix: Only catch expected exceptions, not DatabaseError etc.
        project = None
    except Exception as e:
        logger.error(f'Unexpected error in projects context processor: {e}')
        project = None
    return {
        'projects': projects,
        'current_project': project
    }

def version_context(request):
    return {
        'RENGINE_CURRENT_VERSION': settings.RENGINE_CURRENT_VERSION
    }

def user_preferences(request):
    if hasattr(request, 'user_preferences'):
        return {'user_preferences': request.user_preferences}
    return {}