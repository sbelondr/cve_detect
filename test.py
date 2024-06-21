from transformers import pipeline


question = "How many programming languages does BLOOM support?"
context = "BLOOM has 176 billion parameters and can generate text in 46 languages natural languages and 13 programming languages."

question_answerer = pipeline("question-answering", model="my_awesome_qa_model")

question_answerer(question=question, context=context)