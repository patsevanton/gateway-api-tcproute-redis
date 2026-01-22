package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
)

func main() {
	// Получение адреса Redis из переменной окружения
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		fmt.Fprintln(os.Stderr, "REDIS_HOST не установлен")
		os.Exit(1)
	}

	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "443"
	}

	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	fmt.Printf("Подключение к Redis через Gateway: %s\n", redisAddr)

	// Проверка DNS разрешения
	fmt.Printf("Проверка DNS для %s...\n", redisHost)
	ips, err := net.LookupHost(redisHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка DNS разрешения: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("DNS разрешен: %v\n", ips)

	// TLS конфигурация: по умолчанию проверяем сертификат через Root CA,
	// который передается в контейнер через k8s Secret.
	//
	// - REDIS_CA_CERT: путь к ca.crt (по умолчанию /etc/redis-ca/ca.crt)
	// - REDIS_INSECURE_SKIP_VERIFY=true: отключить проверку (не рекомендуется)
	caPath := os.Getenv("REDIS_CA_CERT")
	if caPath == "" {
		caPath = "/etc/redis-ca/ca.crt"
	}

	insecure := os.Getenv("REDIS_INSECURE_SKIP_VERIFY") == "true"

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: redisHost,
	}

	if insecure {
		tlsCfg.InsecureSkipVerify = true
		fmt.Fprintln(os.Stderr, "Внимание: включен REDIS_INSECURE_SKIP_VERIFY=true (проверка TLS отключена)")
	} else {
		caBytes, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Не удалось прочитать CA сертификат (%s): %v\n", caPath, err)
			fmt.Fprintln(os.Stderr, "Смонтируйте Secret с ca.crt или установите REDIS_INSECURE_SKIP_VERIFY=true")
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			fmt.Fprintf(os.Stderr, "Не удалось распарсить CA сертификат (%s)\n", caPath)
			os.Exit(1)
		}
		tlsCfg.RootCAs = pool
	}

	// Настройка Redis клиента с TLS
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
		TLSConfig: &tls.Config{
			MinVersion:         tlsCfg.MinVersion,
			ServerName:         tlsCfg.ServerName,
			RootCAs:            tlsCfg.RootCAs,
			InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
		},
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})
	defer rdb.Close()

	// Контекст с таймаутом для всех операций
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Получение аргументов командной строки
	if len(os.Args) > 1 {
		// Проверка подключения с выводом статуса
		fmt.Println("Проверка подключения к Redis...")
		_, err := rdb.Ping(ctx).Result()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка подключения к Redis: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Подключение успешно!")
		// Выполнение команды Redis
		cmd := os.Args[1]
		args := os.Args[2:]

		var result interface{}

		switch cmd {
		case "PING":
			result, err = rdb.Ping(ctx).Result()
		case "SET":
			if len(args) < 2 {
				fmt.Println("Использование: SET <key> <value>")
				os.Exit(1)
			}
			err = rdb.Set(ctx, args[0], args[1], 0).Err()
			if err == nil {
				result = "OK"
			}
		case "GET":
			if len(args) < 1 {
				fmt.Println("Использование: GET <key>")
				os.Exit(1)
			}
			result, err = rdb.Get(ctx, args[0]).Result()
		case "DEL":
			if len(args) < 1 {
				fmt.Println("Использование: DEL <key>")
				os.Exit(1)
			}
			result, err = rdb.Del(ctx, args...).Result()
		case "KEYS":
			pattern := "*"
			if len(args) > 0 {
				pattern = args[0]
			}
			result, err = rdb.Keys(ctx, pattern).Result()
		case "FLUSHDB":
			err = rdb.FlushDB(ctx).Err()
			if err == nil {
				result = "OK"
			}
		default:
			fmt.Fprintf(os.Stderr, "Неизвестная команда: %s\n", cmd)
			fmt.Println("Поддерживаемые команды: PING, SET, GET, DEL, KEYS, FLUSHDB")
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка выполнения команды: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(result)
	} else {
		// Интерактивный режим (простой)
		fmt.Println("Интерактивный режим. Для выхода используйте Ctrl+C")
		fmt.Println("Примеры команд:")
		fmt.Println("  SET key value")
		fmt.Println("  GET key")
		fmt.Println("  DEL key")
		fmt.Println("  KEYS *")

		// Простой цикл для выполнения команд
		for {
			var input string
			fmt.Print("redis> ")
			fmt.Scanln(&input)

			if input == "quit" || input == "exit" {
				break
			}

			// Здесь можно добавить парсинг команд, но для простоты оставим базовый функционал
		}
	}
}
