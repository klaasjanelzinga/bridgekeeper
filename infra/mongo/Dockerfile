FROM mongo:5.0.2-focal

COPY init-mongo.sh /docker-entrypoint-initdb.d/
COPY mongo.conf /etc/

VOLUME /data/db
