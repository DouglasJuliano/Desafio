FROM python:3.8-slim
COPY . /desafio
WORKDIR /desafio
RUN pip install -r requirements.txt
CMD ["python3", "main.py"]