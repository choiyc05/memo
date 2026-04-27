from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
  host_ip: str
  kafka_server: str = "localhost:9092"
  kafka_topic: str = "email"
  mail_username: str
  mail_password: str
  mail_from: str
  mail_port: int = 587
  mail_server: str = "smtp.gmail.com"
  mail_from_name: str = "edu"
  mail_starttls: bool = True
  mail_ssl_tls: bool = False

  model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
  )

settings = Settings()
