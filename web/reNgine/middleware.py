from dashboard.models import UserPreferences


class UserPreferencesMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		if request.user.is_authenticated:
			# MED-01 fix: Cache user preferences in session to avoid DB query per request
			prefs_cache_key = f'_user_prefs_{request.user.pk}'
			cached_prefs_id = request.session.get(prefs_cache_key)
			if cached_prefs_id:
				try:
					request.user_preferences = UserPreferences.objects.get(pk=cached_prefs_id)
				except UserPreferences.DoesNotExist:
					cached_prefs_id = None
			if not cached_prefs_id:
				request.user_preferences, _ = UserPreferences.objects.get_or_create(user=request.user)
				request.session[prefs_cache_key] = request.user_preferences.pk
		return self.get_response(request)
