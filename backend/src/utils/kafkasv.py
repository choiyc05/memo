import json
import asyncio
import threading
from kafka import KafkaProducer, KafkaConsumer
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

from settings import settings

# Kafka Producer 설정
kafkaProducer = KafkaProducer(
  bootstrap_servers=settings.kafka_server,
  value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

# mail config 설정
mailConf = ConnectionConfig(
  MAIL_USERNAME = settings.mail_username,
  MAIL_PASSWORD = settings.mail_password,
  MAIL_FROM = settings.mail_from,
  MAIL_PORT = settings.mail_port,
  MAIL_SERVER = settings.mail_server,
  MAIL_FROM_NAME = settings.mail_from_name,
  MAIL_STARTTLS = settings.mail_starttls,
  MAIL_SSL_TLS = settings.mail_ssl_tls,
  USE_CREDENTIALS = settings.use_credentials,
  VALIDATE_CERTS = settings.validate_certs
)
fastMail = FastMail(mailConf)

# Producer 함수 
def sendToKafka(data):
    """API 서버에서 메시지를 보낼 때 사용"""
    kafkaProducer.send(settings.kafka_topic, data)
    kafkaProducer.flush()

# Email html
# html1 = 사내 직원 초대 이메일
html1 = f"""
    <h1>직원 초대 메일</h1>
    <p>아래 링크를 통해 가입 후 로그인하세요.</p>
    <p>link</p>
  """
# html2 = 컨설턴트 초대 이메일
html2 = f"""
    <h1>컨설턴트 초대</h1>
    <p>아래 링크를 통해 가입 후 로그인하세요.</p>
    <p>link</p>
  """

# Consumer 이메일 발송 함수
async def handleEmailJob(data):
    """consumer1: 사내 직원 초대 이메일 발송"""
    message = MessageSchema(
        subject="사내 직원 초대",
        recipients=[data.get("email")],
        body=html1,
        subtype=MessageType.html
    )
    await fastMail.send_message(message)

# Consumer 함수
def runEmailConsumer():
    """이메일 토픽 컨슈머 루프"""
    consumer = KafkaConsumer(
        settings.kafka_topic, 
        bootstrap_servers=settings.kafka_server,
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8"))
    )
    for message in consumer:
        asyncio.run(handleEmailJob(message.value))

def startConsumer():
    """컨슈머 시작 함수"""
    emailThread = threading.Thread(target=runEmailConsumer, daemon=True)
    emailThread.start()
