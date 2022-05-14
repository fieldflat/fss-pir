FROM golang:1.18.2-alpine3.15

ENV ROOT=/go/src/app
WORKDIR ${ROOT}

RUN apk update && apk add git

COPY ./main.go ${ROOT}
COPY go.mod ${ROOT}
COPY ./src ${ROOT}/src
COPY ./jsondata/data.json ${ROOT}/jsondata/data.json
COPY ./keys/NumBits ${ROOT}/keys/NumBits
COPY ./keys/PrfKeys ${ROOT}/keys/PrfKeys

RUN go mod tidy