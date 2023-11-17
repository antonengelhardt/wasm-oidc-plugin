FROM alpine:latest

RUN apk update && apk add chromium chromium-chromedriver python3 py3-pip curl

COPY . .
RUN pip install -r requirements.txt

CMD ["pytest", "test.py"]
