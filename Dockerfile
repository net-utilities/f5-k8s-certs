FROM python:alpine3.16 as pythonBuilder
WORKDIR /home/root/server
COPY . .
RUN pip3 install --target=/home/root/server/dependencies -r requirements.txt

FROM python:alpine3.16
WORKDIR /home/root/server
COPY --from=pythonBuilder	/home/root/server .
ENV PYTHONPATH="${PYTHONPATH}:/home/root/server/dependencies"
ENTRYPOINT ["/usr/local/bin/python", "./main.py"]
