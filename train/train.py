#!/usr/bin/env python

import nltk
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from scipy.sparse import hstack
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import string
import pandas as pd
from scipy.sparse import hstack


from transformers import BertTokenizer, BertForTokenClassification, BertForSequenceClassification, Trainer, TrainingArguments
from transformers import BertConfig
import torch

import spacy

class CustomDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: val[idx] for key, val in self.encodings.items()}
        item['labels'] = self.labels[idx]
        return item

    def __len__(self):
        return len(self.labels)

def preprocess_text(text):
    doc = nlp(text.lower())
    return ' '.join([token.lemma_ for token in doc if not token.is_stop and not token.is_punct])

nltk.download('stopwords')
nltk.download('wordnet')

stop_words = set(stopwords.words('english'))
lemmatizer = WordNetLemmatizer()


nlp = spacy.load('en_core_web_sm')


data = pd.read_csv('example.csv')

# print(data.head())
data = data.dropna()

data['description'] = data['description'].apply(preprocess_text)

train_texts, test_texts, train_labels, test_labels = train_test_split(
    data['description'], data['product'], test_size=0.2, random_state=42)



# Load BERT tokenizer
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

# Tokenize text
train_encodings = tokenizer(train_texts.tolist(), truncation=True, padding=True, max_length=512)
test_encodings = tokenizer(test_texts.tolist(), truncation=True, padding=True, max_length=512)

label_map = {label: idx for idx, label in enumerate(data['product'].unique())}
train_labels = [label_map[label] for label in train_labels]
test_labels = [label_map[label] for label in test_labels]

# Convert to tensor
train_encodings = {key: torch.tensor(val) for key, val in train_encodings.items()}
test_encodings = {key: torch.tensor(val) for key, val in test_encodings.items()}
train_labels = torch.tensor(train_labels)
test_labels = torch.tensor(test_labels)




train_dataset = CustomDataset(train_encodings, train_labels)
test_dataset = CustomDataset(test_encodings, test_labels)

model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=len(label_map))

training_args = TrainingArguments(
    output_dir='./results',
    num_train_epochs=3,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=64,
    warmup_steps=500,
    weight_decay=0.01,
    logging_dir='./logs',
    logging_steps=10,
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset
)

trainer.train()


# Sauvegarder le modèle et le tokenizer
model.save_pretrained('./saved_model')
tokenizer.save_pretrained('./saved_token')

