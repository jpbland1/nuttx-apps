#include <user_settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>
#define SERV_PORT 443

const char* wolfssl_root_pem =
"-----BEGIN CERTIFICATE-----"
"MIIGYTCCBUmgAwIBAgIQAQ3tJI6fRNckZstfdB/dTzANBgkqhkiG9w0BAQsFADBY"
"MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEuMCwGA1UE"
"AxMlR2xvYmFsU2lnbiBBdGxhcyBSMyBEViBUTFMgQ0EgMjAyMiBRMjAeFw0yMjA3"
"MDkxNjQ1MDBaFw0yMzA4MTAxNjQ0NTlaMBoxGDAWBgNVBAMMD3d3dy53b2xmc3Ns"
"LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANBpH+3RKFweZp/+"
"3F1RMfrmylkp62HmXmwBLvs6YqCz30dlU99rZHgfe45cd8wNDpxhjvJclz181OUY"
"/kIry9VAMYnuiKmSGaCsCHZSX3CB2/a0nISsIVXwF76F9cRUNyI5mCgnIVpxbs1v"
"Fn/7f2l0q8cha4pbQHSOeYOvGrJGwbioELsJy3CxY5Y5iQ1hrdv1tjPwJjsZ8Z+3"
"kxG9tVj5ctolKLWY71Ul+u8GcLq0yi+gUlFxMqp8mMwS71iz6PIJ7+0p9Smv2RgN"
"BY6nb/uNk3DiipXeEq8CMFz/TOHgVNOvZxY1d+0xAk3TdCGHglVtBxmEHTXmqpon"
"YSVRrA8CAwEAAaOCA2MwggNfMBoGA1UdEQQTMBGCD3d3dy53b2xmc3NsLmNvbTAO"
"BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0G"
"A1UdDgQWBBQ74/Kk5oqqGGN7TeQXc/uA8LHDGjBXBgNVHSAEUDBOMAgGBmeBDAEC"
"ATBCBgorBgEEAaAyCgEDMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh"
"bHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZ4GCCsGAQUFBwEB"
"BIGRMIGOMEAGCCsGAQUFBzABhjRodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9j"
"YS9nc2F0bGFzcjNkdnRsc2NhMjAyMnEyMEoGCCsGAQUFBzAChj5odHRwOi8vc2Vj"
"dXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2F0bGFzcjNkdnRsc2NhMjAyMnEy"
"LmNydDAfBgNVHSMEGDAWgBRiqnShV6Dt4sTkSJgU49PcrnlRJTBIBgNVHR8EQTA/"
"MD2gO6A5hjdodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzYXRsYXNyM2R2"
"dGxzY2EyMDIycTIuY3JsMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgCt9776"
"fP8QyIudPZwePhhqtGcpXc+xDCTKhYY069yCigAAAYHj2aSjAAAEAwBHMEUCIQD4"
"L2ixrkVj4VPoftyhufbok+NBuVJYFaUBJZp9Z7aR9QIgbAF+Dldja1nuOVadrpAA"
"ld7m3anJOlK/i0LVYnj4ziEAdgCzc3cH4YRQ+GOG1gWp3BEJSnktsWcMC4fc8AMO"
"eTalmgAAAYHj2aTLAAAEAwBHMEUCIQDZ7xcMpY1gcMW7+AQkjo5iczSk3KiGSOzc"
"oufu1uXCOgIgA5lalhcZs8w5cISqqN2b5CDYjP92ylBVMguFm7RJdCEAdgBvU3as"
"MfAxGdiZAKRRFf93FRwR2QLBACkGjbIImjfZEwAAAYHj2aUaAAAEAwBHMEUCIQCH"
"xITut3GiNKmZkwCIge+WO179jup1fIrcAabB/LEJIAIgCknIwa1895IGlOrnrvDA"
"0HD1VDeoCmAsBkT9yFB/jNUwDQYJKoZIhvcNAQELBQADggEBADw1bfG0HiCIOH00"
"mZ90ZJMHyElmVURVRdOBn1OeX+nnaWV8UmiUJRVLCBgKUz23koqiFwBKlRTX5BSn"
"w5ea4EkdoDEN8G/zXqDAy5TCGoeLRY6XyZcrhf9zdpHrrASRhWN4mEfcM+TcngLf"
"2kGQgMt/0gUfGq/jlk5TzAKnao6OHgZ2czr5KD+1DYqa2yah44rcgNKy0/6mBOwV"
"jx/oNvY1ePopS9TLFg5QYUwePyL5NzOjMPOPuAKwXY8k+SkDhyojfvt0gCYBXl/w"
"JEcxrWX4ETP90Ht10AKmTHJdNziE1Z2LpwhDfXscf4pu1smWCLeAP/X6Ng5/XYKV"
"A2W0nis="
"-----END CERTIFICATE-----"
"-----BEGIN CERTIFICATE-----"
"MIIEjzCCA3egAwIBAgIQe55B9j2xiq6v7XsTYE8UkjANBgkqhkiG9w0BAQsFADBM"
"MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv"
"YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMjAxMjYxMjAwMDBaFw0y"
"NTAxMjYwMDAwMDBaMFgxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu"
"IG52LXNhMS4wLAYDVQQDEyVHbG9iYWxTaWduIEF0bGFzIFIzIERWIFRMUyBDQSAy"
"MDIyIFEyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNQY1F/iJfnt"
"bzEXilBoUC+hIHTPePiWT46DmcuO6dUZ0QOu9m9DQfcQUNdq9btVW2UfwcLfkt4z"
"IxfqgVGQNUU3Ua+Pod4QsfaIB8MQhbcpEpunvSwEZAe5udhsorbXs0xMEPsmBDXE"
"qZYcGoQAPKBy03RRUgsiSmq+saJ4O1LddsnHdGJzXbj5ugi4kkVymmjzwqXFwvmE"
"moFcMJwj2ZHUIdwIy7s/yXiVDTC/ZfE/jqooaBJh5bM4767Ml9k6mswwvIWaZfPk"
"0ra8Fwz++DwZp6PqeSB9qYpnI2ww6Zvy5teoRbuPKIWvpGfM3G25vH+zEXCj7757"
"D6LJx9OGgQIDAQABo4IBXzCCAVswDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQG"
"CCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW"
"BBRiqnShV6Dt4sTkSJgU49PcrnlRJTAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpj"
"move4t0bvDB7BggrBgEFBQcBAQRvMG0wLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3Nw"
"Mi5nbG9iYWxzaWduLmNvbS9yb290cjMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9zZWN1"
"cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjMuY3J0MDYGA1UdHwQvMC0w"
"K6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yMy5jcmwwIQYD"
"VR0gBBowGDAIBgZngQwBAgEwDAYKKwYBBAGgMgoBAzANBgkqhkiG9w0BAQsFAAOC"
"AQEAlHgai54B6+AFJHCaJHAnf3UqiRYu4GWSun24yqT5Kk4yeQ+HsKBK1evOL/0n"
"kRlIlMwnJ8oQ448aGeXmKt81WGNp1hNOh7exm6dK3LCJLp/SWlDn8CckJwMgrbhl"
"IcoAkI6v3hxmaX5w/74yRXWxmJ3CD66Bb8iitTJ8t0kUfoF27BezmtYoZR1iwdCe"
"jHX5b7fiPQ2sL6+1d+nmzwJn8SgRz3wDNLnh9VjruSv3WmCEkFGfXkQ34BWGYyNK"
"WCumLL0+8+IXu16B4TttpjVhFRg2m9J81NgT9gfSOUdMLCKoofK6vIg5ickX4cj4"
"x8rrZXQpA2/0Xn+AFLRxVuA0YA=="
"-----END CERTIFICATE-----"
"-----BEGIN CERTIFICATE-----"
"MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G"
"A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp"
"Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4"
"MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG"
"A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI"
"hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8"
"RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT"
"gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm"
"KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd"
"QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ"
"XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw"
"DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o"
"LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU"
"RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp"
"jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK"
"6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX"
"mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs"
"Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH"
"WD9f"
"-----END CERTIFICATE-----";

int main()
{
    int ret;
    int sockfd;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD* method;
    struct  sockaddr_in servAddr;
    const char message[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.wolfssl.com\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Referer: https://www.google.com/\r\n"
        "DNT: 1\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: cross-site\r\n"
        "Pragma: no-cache\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n";
    char rdbuff[512];
    unsigned int contentLength = 0;
    int i = 0;
    int headerEndIndex = 0;
    const char headerEnd[] = "\r\n\r\n";
    const char contentLengthStr[] = "Content-Length: ";

        /* create and set up socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    servAddr.sin_addr.s_addr = inet_addr("151.101.130.137");

        /* connect to socket */
    if((ret = connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr))) != 0){
        printf("connect error %d\n", ret);
        return ret;
    }

        /* initialize wolfssl library */
    wolfSSL_Init();
    method = wolfTLSv1_3_client_method(); /* use TLS v1.3 */
    //method = wolfTLSv1_2_client_method(); /* use TLS v1.2 */

        /* make new ssl context */
    if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
        printf("wolfSSL_CTX_new error\n");
    }

        /* make new wolfSSL struct */
    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
        printf("wolfSSL_CTX_new error\n");
    }

        /* Add cert to ctx */
    if ((ret = (wolfSSL_CTX_load_verify_buffer(ctx, wolfssl_root_pem,
        strlen(wolfssl_root_pem), SSL_FILETYPE_PEM))) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_locations error %d\n", ret);
        return ret;
    }

    /*
    if ((ret = (wolfSSL_CTX_load_verify_buffer(ctx, wolfssl_site_pem,
        strlen(wolfssl_site_pem), SSL_FILETYPE_PEM))) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_locations error %d\n", ret);
        return ret;
    }
    */

    /* set sni */
    /*
    if ((ret = (wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "wolfssl.com",
        strlen("wolfssl.com")))) != SSL_SUCCESS) {
        printf("wolfSSL_CTX_load_verify_locations error %d\n", ret);
        return ret;
    }
    */

        /* Connect wolfssl to the socket, server, then send message */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != SSL_SUCCESS) {
        printf("wolfSSL_set_fd error %d\n", ret);
        return ret;
    }

    /*
    wolfSSL_Debugging_ON();
    */

    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        printf("wolfSSL_connect error %d\n", ret);
        return ret;
    }

    if ((ret = wolfSSL_write(ssl, message, strlen(message))) !=
        strlen(message)) {
        printf("wolfSSL_write error %d\n", ret);
        return ret;
    }

    do
    {
        ret = wolfSSL_read(ssl, rdbuff, sizeof(rdbuff));

        if (ret <= 0) {
            printf("wolfSSL_read error %d\n", ret);
            return ret;
        }
        else {
            printf("%.*s\n", ret, rdbuff);
        }

        if (headerEndIndex < strlen(headerEnd)) {
            for (i = 0; i < ret; i++) {
                if (rdbuff[i] == headerEnd[headerEndIndex])
                    headerEndIndex++;
                else
                    headerEndIndex = 0;

                if (contentLength == 0 && strncmp(rdbuff + i, contentLengthStr,
                    strlen(contentLengthStr)) == 0) {
                    contentLength = atoi(rdbuff + i + strlen(contentLengthStr));
                }

                if (headerEndIndex == strlen(headerEnd)) {
                    contentLength -= ret - i + - 1;
                    break;
                }
            }
        }
        else
        {
            contentLength -= ret;
        }
    } while (headerEndIndex < strlen(headerEnd) || contentLength > 0);

        /* frees all data before client termination */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
