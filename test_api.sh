#!/bin/bash
curl -X POST https://iapi-test.merck.com/gpt/v2/gemini-2-5-pro \
  -H "Content-Type: application/json" \
  -H "X-Merck-APIKey: jWnbLKsjS5PdX5fxisSX4DHhZQycbFSJ" \
  -d '{
    "contents": {
      "role": "user",
      "parts": {
        "text": "What is threat modeling?"
      }
    },
    "safety_settings": {
      "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
      "threshold": "BLOCK_LOW_AND_ABOVE"
    },
    "generation_config": {
      "temperature": 0.7,
      "topP": 0.9,
      "topK": 40,
      "maxOutputTokens": 2048
    }
  }'
