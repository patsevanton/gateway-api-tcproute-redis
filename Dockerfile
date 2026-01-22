# Многостадийная сборка
FROM golang:1.21-alpine AS builder

# Установка необходимых инструментов
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Копирование go.mod и go.sum (если есть)
COPY go.mod go.sum* ./

# Загрузка зависимостей
RUN go mod download

# Копирование исходного кода
COPY main.go .

# Обновление зависимостей после копирования кода
RUN go mod tidy

# Сборка приложения
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o redis-client main.go

# Финальный образ
FROM alpine:latest

# Установка CA сертификатов для TLS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Копирование бинарника из builder
COPY --from=builder /build/redis-client .

# Переменная окружения для выбора Redis хоста
# REDIS_HOST может быть redis1.apatsev.org.ru или redis2.apatsev.org.ru
ENV REDIS_HOST=redis1.apatsev.org.ru
ENV REDIS_PORT=443

# Исполняемый файл
ENTRYPOINT ["/app/redis-client"]
CMD []