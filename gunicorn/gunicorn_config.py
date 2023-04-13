import multiprocessing

# Set the server bind address
bind = "127.0.0.1:8000"

# Set the number of worker processes
workers = multiprocessing.cpu_count() * 2 + 1

# Set worker timeout
timeout = 600

keepalive=2

# Set the maximum number of requests a worker will process before restarting
max_requests = 1000

# Set the maximum number of requests a worker will process before graceful restart
max_requests_jitter = 50

# Set the access log file path
accesslog = "/var/log/gunicorn/access.log"

# Set the error log file path
errorlog = "/var/log/gunicorn/error.log"

# Set the log level
loglevel = "info"


#added
# Use the GeventWebSocketWorker worker class for long-polling support
worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'
#change
