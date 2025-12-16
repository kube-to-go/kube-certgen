ARG APP=kube-certgen

FROM golang:1.25-alpine3.22 AS build

ARG APP

WORKDIR /opt/app

COPY go.mod go.sum .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ${APP} .


FROM busybox:stable-musl

ARG APP
ENV APP=${APP}

WORKDIR /opt/app

COPY --from=build /opt/app/${APP} .
RUN mkdir -pv /usr/local/bin && \
	ln -sv /opt/app/${APP} /usr/local/bin/app

ENTRYPOINT ["app"]