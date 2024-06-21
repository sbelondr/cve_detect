from transformers import BertTokenizer, BertForTokenClassification, BertForSequenceClassification, Trainer, TrainingArguments
from transformers import BertConfig

from transformers import TextClassificationPipeline
import spacy
import torch
import pandas as pd

nlp = spacy.load('en_core_web_sm')

def preprocess_text(text):
    doc = nlp(text.lower())
    return ' '.join([token.lemma_ for token in doc if not token.is_stop and not token.is_punct])



def predict_new_values(model, tokenizer, new_text):
    new_text = preprocess_text(new_text)
    encodings = tokenizer(new_text, truncation=True, padding=True, max_length=512, return_tensors='pt')
    output = model(**encodings)
    prediction_index = torch.argmax(output.logits, dim=1).item()
    prediction_label = index_to_label[prediction_index]
    return prediction_label

data = pd.read_csv('example.csv')
label_map = {label: idx for idx, label in enumerate(data['product'].unique())}

index_to_label = {v: k for k, v in label_map.items()}


model = BertForSequenceClassification.from_pretrained('./saved_model')
tokenizer = BertTokenizer.from_pretrained('./saved_token' )

new_data = {
    'description': [
        "In the Linux kernel, the following vulnerability has been resolved: fs/9p: only translate RWX permissions for plain 9P2000 Garbage in plain 9P2000's perm bits is allowed through, which causes it to be able to set (among others) the suid bit. This was presumably not the intent since the unix extended bits are handled explicitly and conditionally on .u.",
        "The Active Admin (aka activeadmin) framework before 3.2.2 for Ruby on Rails allows stored XSS in certain situations where users can create entities (to be later edited in forms) with arbitrary names, aka a \"dynamic form legends\" issue. 4.0.0.beta7 is also a fixed version.",
        "Linux",
        "API Kong injection sql",
        "A vulnerability in the management and VPN web servers for Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to incomplete error checking when parsing an HTTP header. An attacker could exploit this vulnerability by sending a crafted HTTP request to a targeted web server on a device. A successful exploit could allow the attacker to cause a DoS condition when the device reloads."
    ]
}

for desc in new_data['description']:
    predicted_value = predict_new_values(model, tokenizer, desc)
    print(predicted_value)

