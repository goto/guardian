FROM alpine:3.13

RUN apk add curl
RUN apk add openssl

RUN apk add --no-cache ca-certificates && update-ca-certificates

# odps package has an unhandled (panicking) error that requires this pkg to be installed to avoid the panic:
# https://github.com/aliyun/aliyun-odps-go-sdk/blob/master/odps/restclient/rest_client.go#L171
# https://github.com/aliyun/aliyun-odps-go-sdk/blob/master/odps/common/http_const.go#L38
RUN apk --no-cache add tzdata 

RUN curl --output /usr/local/share/ca-certificates/SectigoRSADomainValidationSecureServerCA.crt http://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt

RUN openssl x509 -inform DER -in /usr/local/share/ca-certificates/SectigoRSADomainValidationSecureServerCA.crt -out /usr/local/share/ca-certificates/SectigoRSADomainValidationSecureServerCA.pem -text
RUN update-ca-certificates

COPY guardian .

EXPOSE 8080
ENTRYPOINT ["./guardian"]
