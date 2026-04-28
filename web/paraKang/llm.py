
import openai
import re
from paraKang.common_func import (
	get_open_ai_key, 
	parse_llm_vulnerability_report,
	get_available_ollama_model_names
)
from paraKang.definitions import VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE, ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, VULNERABILITY_FINDINGS_GPT_SYSTEM_PROMPT, OLLAMA_INSTANCE, DEFAULT_GPT_MODELS
from langchain_community.llms import Ollama

from dashboard.models import OllamaSettings


# Fallback models for when Ollama is not available or to show recommended models
DEFAULT_RECOMMENDED_MODELS = ['mistral', 'neural-chat', 'dolphin-mixtral', 'llama2', 'openchat']
DEFAULT_OLLAMA_MODEL = DEFAULT_RECOMMENDED_MODELS[0]
DEFAULT_OPENAI_MODEL = 'gpt-3.5-turbo'
DEFAULT_GPT_MODEL_NAMES = {model['name'] for model in DEFAULT_GPT_MODELS}


def resolve_ollama_model_name(selected_model_name):
	available_ollama_models = get_available_ollama_model_names()
	if not available_ollama_models:
		return None
	if selected_model_name in DEFAULT_GPT_MODEL_NAMES:
		return available_ollama_models[0]
	if selected_model_name.split(':')[0] in available_ollama_models:
		return selected_model_name
	return available_ollama_models[0]


class LLMVulnerabilityReportGenerator:

	def __init__(self, logger):
		selected_model = OllamaSettings.objects.first()
		
		selected_model_name = selected_model.selected_model if selected_model else DEFAULT_OLLAMA_MODEL
		# Keep a GPT selection for OpenAI usage, but resolve an Ollama-safe model name for fallback.
		self.model_name = resolve_ollama_model_name(selected_model_name)
		self.use_ollama = selected_model.use_ollama if selected_model else False
		self.openai_api_key = None
		self.logger = logger
	
	def get_vulnerability_description(self, description):
		"""Generate Vulnerability Description using GPT.

		Args:
			description (str): Vulnerability Description message to pass to GPT.

		Returns:
			(dict) of {
				'description': (str)
				'impact': (str),
				'remediation': (str),
				'references': (list) of urls
			}
		"""
		self.logger.info(f"Generating Vulnerability Description for: {description}")
		self.logger.info(f"use_ollama={self.use_ollama}, model_name={self.model_name}")
		
		response_content = None
		
		# Use a known-good OpenAI model when OpenAI is active.
		openai_model = DEFAULT_OPENAI_MODEL
		ollama_model = self.model_name
		if self.use_ollama and not ollama_model:
			return {
				'status': False,
				'error': 'No Ollama models are installed. Pull a model first with ollama pull <model> or select an installed model.'
			}
		
		if self.use_ollama:
			self.logger.info(f"Using Ollama for Vulnerability Description Generation with model: {ollama_model}")
			prompt = VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE + "\nUser: " + description
			prompt = re.sub(r'\t', '', prompt)
			try:
				llm = Ollama(
					base_url=OLLAMA_INSTANCE, 
					model=ollama_model,
					timeout=600,
				)
				response_content = llm.invoke(prompt)
			except Exception as e:
				self.logger.error(f"Ollama error: {e}")
				return {
					'status': False,
					'error': f'Ollama error: {str(e)}'
				}
		else:
			# Try OpenAI first, then fallback to Ollama
			self.logger.info(f'Checking OpenAI API for Vulnerability Description Generation')
			openai_api_key = get_open_ai_key()
			
			# Strict validation: check if key is valid (not None, not empty, not "None" string)
			is_key_valid = (openai_api_key and 
						   isinstance(openai_api_key, str) and 
						   openai_api_key.strip() and 
						   openai_api_key.lower() != 'none')
			
			self.logger.info(f'OpenAI API Key: {"Valid" if is_key_valid else "Not set or invalid"} (value: {openai_api_key})')
			
			if is_key_valid:
				try:
					prompt = re.sub(r'\t', '', VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE)
					# Thread-safe: use client instance instead of global openai.api_key
					client = openai.OpenAI(api_key=openai_api_key)
					gpt_response = client.chat.completions.create(
						model=openai_model,
						messages=[
							{'role': 'system', 'content': prompt},
							{'role': 'user', 'content': description}
						]
					)
					response_content = gpt_response.choices[0].message.content
				except Exception as e:
					self.logger.warning(f'OpenAI API failed: {e}. Attempting Ollama fallback.')
					openai_api_key = None  # Force fallback
			
			# Fallback to Ollama if OpenAI key not valid or OpenAI failed
			if not is_key_valid or not response_content:
				self.logger.warning(f'Falling back to Ollama for Vulnerability Description with model: {ollama_model}')
				prompt = VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE + "\nUser: " + description
				prompt = re.sub(r'\t', '', prompt)
				try:
					llm = Ollama(
						base_url=OLLAMA_INSTANCE, 
						model=ollama_model,
						timeout=600,
					)
					response_content = llm.invoke(prompt)
				except Exception as e:
					self.logger.error(f"Ollama fallback error: {e}")
					return {
						'status': False,
						'error': f'Both OpenAI and Ollama failed: {str(e)}'
					}
		
		if not response_content:
			return {
				'status': False,
				'error': 'No response content from LLM'
			}
			
		response = parse_llm_vulnerability_report(response_content)

		if not response:
			return {
				'status': False,
				'error': 'Failed to parse LLM response'
			}

		return {
			'status': True,
			'description': response.get('description', ''),
			'impact': response.get('impact', ''),
			'remediation': response.get('remediation', ''),
			'references': response.get('references', []),
		}


class LLMAttackSuggestionGenerator:

	def __init__(self, logger):
		selected_model = OllamaSettings.objects.first()
		
		selected_model_name = selected_model.selected_model if selected_model else DEFAULT_OLLAMA_MODEL
		# Keep a GPT selection for OpenAI usage, but resolve an Ollama-safe model name for fallback.
		self.model_name = resolve_ollama_model_name(selected_model_name)
		self.use_ollama = selected_model.use_ollama if selected_model else False
		self.openai_api_key = None
		self.logger = logger

	def get_attack_suggestion(self, user_input):
		'''
			user_input (str): input for gpt
		'''
		self.logger.info(f"use_ollama={self.use_ollama}, model_name={self.model_name}")
		response_content = None
		
		# Use a known-good OpenAI model when OpenAI is active.
		openai_model = DEFAULT_OPENAI_MODEL
		ollama_model = self.model_name
		if self.use_ollama and not ollama_model:
			return {
				'status': False,
				'error': 'No Ollama models are installed. Pull a model first with ollama pull <model> or select an installed model.',
				'input': user_input
			}
		
		if self.use_ollama:
			self.logger.info(f"Using Ollama for Attack Suggestion Generation with model: {ollama_model}")
			prompt = ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT + "\nUser: " + user_input	
			prompt = re.sub(r'\t', '', prompt)
			try:
				llm = Ollama(
					base_url=OLLAMA_INSTANCE, 
					model=ollama_model,
					timeout=600
				)
				response_content = llm.invoke(prompt)
				self.logger.info(response_content)
			except Exception as e:
				self.logger.error(f"Ollama attack suggestion error: {e}")
				return {
					'status': False,
					'error': f'Ollama error: {str(e)}',
					'input': user_input
				}
		else:
			# Try OpenAI first, then fallback to Ollama
			self.logger.info(f'Checking OpenAI API for Attack Suggestion Generation')
			openai_api_key = get_open_ai_key()
			
			# Strict validation: check if key is valid (not None, not empty, not "None" string)
			is_key_valid = (openai_api_key and 
						   isinstance(openai_api_key, str) and 
						   openai_api_key.strip() and 
						   openai_api_key.lower() != 'none')
			
			self.logger.info(f'OpenAI API Key: {"Valid" if is_key_valid else "Not set or invalid"} (value: {openai_api_key})')
			
			if is_key_valid:
				try:
					prompt = re.sub(r'\t', '', ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT)
					# Thread-safe: use client instance instead of global openai.api_key
					client = openai.OpenAI(api_key=openai_api_key)
					gpt_response = client.chat.completions.create(
						model=openai_model,
						messages=[
							{'role': 'system', 'content': prompt},
							{'role': 'user', 'content': user_input}
						]
					)
					response_content = gpt_response.choices[0].message.content
				except Exception as e:
					self.logger.warning(f'OpenAI API failed: {e}. Attempting Ollama fallback.')
					openai_api_key = None  # Force fallback
			
			# Fallback to Ollama if OpenAI key not valid or OpenAI failed
			if not is_key_valid or not response_content:
				self.logger.warning(f'Falling back to Ollama for Attack Suggestion with model: {ollama_model}')
				prompt = ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT + "\nUser: " + user_input	
				prompt = re.sub(r'\t', '', prompt)
				try:
					llm = Ollama(
						base_url=OLLAMA_INSTANCE, 
						model=ollama_model,
						timeout=600
					)
					response_content = llm.invoke(prompt)
					self.logger.info(response_content)
				except Exception as e:
					self.logger.error(f"Ollama fallback error: {e}")
					return {
						'status': False,
						'error': f'Both OpenAI and Ollama failed: {str(e)}',
						'input': user_input
					}
		
		if not response_content:
			return {
				'status': False,
				'error': 'No response content from LLM',
				'input': user_input
			}
		
		return {
			'status': True,
			'description': response_content,
			'input': user_input
		}


class LLMVulnerabilityPromptGenerator:

	def __init__(self, logger):
		selected_model = OllamaSettings.objects.first()
		selected_model_name = selected_model.selected_model if selected_model else DEFAULT_OLLAMA_MODEL
		self.model_name = resolve_ollama_model_name(selected_model_name)
		self.use_ollama = selected_model.use_ollama if selected_model else False
		self.logger = logger

	def ask_vulnerability_question(self, vulnerability_context, user_prompt):
		self.logger.info(f"Generating vulnerability prompt response for: {user_prompt}")
		self.logger.info(f"use_ollama={self.use_ollama}, model_name={self.model_name}")

		response_content = None
		openai_model = DEFAULT_OPENAI_MODEL
		ollama_model = self.model_name

		if self.use_ollama and not ollama_model:
			return {
				'status': False,
				'error': 'No Ollama models are installed. Pull a model first with ollama pull <model> or select an installed model.'
			}

		prompt_body = (
			f"Vulnerability Context:\n{vulnerability_context}\n\n"
			f"User Question:\n{user_prompt}"
		)

		if self.use_ollama:
			self.logger.info(f"Using Ollama for vulnerability prompt with model: {ollama_model}")
			prompt = VULNERABILITY_FINDINGS_GPT_SYSTEM_PROMPT + "\n\n" + prompt_body
			prompt = re.sub(r'\t', '', prompt)
			try:
				llm = Ollama(
					base_url=OLLAMA_INSTANCE,
					model=ollama_model,
					timeout=600,
				)
				response_content = llm.invoke(prompt)
			except Exception as e:
				self.logger.error(f"Ollama vulnerability prompt error: {e}")
				return {
					'status': False,
					'error': f'Ollama error: {str(e)}'
				}
		else:
			self.logger.info('Checking OpenAI API for vulnerability prompt generation')
			openai_api_key = get_open_ai_key()
			is_key_valid = (openai_api_key and 
					   isinstance(openai_api_key, str) and 
					   openai_api_key.strip() and 
					   openai_api_key.lower() != 'none')

			if is_key_valid:
				try:
					system_prompt = re.sub(r'\t', '', VULNERABILITY_FINDINGS_GPT_SYSTEM_PROMPT)
					client = openai.OpenAI(api_key=openai_api_key)
					gpt_response = client.chat.completions.create(
						model=openai_model,
						messages=[
							{'role': 'system', 'content': system_prompt},
							{'role': 'user', 'content': prompt_body},
						]
					)
					response_content = gpt_response.choices[0].message.content
				except Exception as e:
					self.logger.warning(f'OpenAI API failed: {e}. Attempting Ollama fallback.')
					openai_api_key = None

			if not is_key_valid or not response_content:
				self.logger.warning(f'Falling back to Ollama for vulnerability prompt with model: {ollama_model}')
				prompt = VULNERABILITY_FINDINGS_GPT_SYSTEM_PROMPT + "\n\n" + prompt_body
				prompt = re.sub(r'\t', '', prompt)
				try:
					llm = Ollama(
						base_url=OLLAMA_INSTANCE,
						model=ollama_model,
						timeout=600,
					)
					response_content = llm.invoke(prompt)
				except Exception as e:
					self.logger.error(f"Ollama fallback error: {e}")
					return {
						'status': False,
						'error': f'Both OpenAI and Ollama failed: {str(e)}'
					}

		if not response_content:
			return {
				'status': False,
				'error': 'No response content from LLM'
			}

		return {
			'status': True,
			'answer': response_content,
		}
		