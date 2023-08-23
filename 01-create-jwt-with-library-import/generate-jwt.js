/**
 * https://www.scaler.com/topics/javascript/import-js-file-in-js/
 * Permite realizar la carga de librerias.
 * @param {*} path De la libreria
 * @param {*} callback Función que se ejecuta posterior a la carga de la libreria.
 */
function loadLibrary(path, callback) {

    const scriptTag = document.createElement("script");

    scriptTag.src = path;

    scriptTag.onload = callback;

    console.log(document.body.appendChild(scriptTag))

    return document.body.appendChild(scriptTag);
}

/**
 * Función principal para generación de token jwt.
 * @param {*} body Request de una petición HTTP.
 */
function getJWTSignature(body) {(

    loadLibrary("../libraries/crypto-js.min.js", (() => {

        loadLibrary("../libraries/jsrsasign-all-min.js", (() => {

            const idempotentReference = JSON.parse(body).idempotentReference;
            const hash = CryptoJS.SHA256(body);
            const hashEncode = CryptoJS.enc.Base64.stringify(hash);
        
            console.log("Encode : ", hashEncode);

            const header = {
                'typ': 'JWT',
                'alg': 'RS256',
                'kid': 'mx_private_key_name'
            };
            
            const payload = {
                'alg': 'SHA256',
                'iss': 'value',
                'hd': hashEncode,
                'nonce': idempotentReference,
                'nbf': KJUR.jws.IntDate.get('now'),
                'iat': KJUR.jws.IntDate.get('now'),
                'exp': KJUR.jws.IntDate.get('now + 1month'),
                'jti': self.crypto.randomUUID()
            };

            const privateKey = '-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbwLXCQ/uEMS6NnF6KVQRA/xKCis82Fp9P5fu9GgJpiHGvq1JmTAbaEPeOU5BoMAx0I1vPXKA/cB9kSw84yxGQmnzaqcVwYDwgVfI6zJ4NF5yHQBD3CrN0fIlZep3/qWQ/jtWWhxXoQExz1yF3CqHPKIDf5bHHgFmxcq0yzYXkYKsl2rAiNSQcdR0ycWDCg1YsVTxqTBvbqRDzg8+aXmgx9UUP4VO29U+8NQ73Ew1MpE7hldoZfvdF8OHfuwaCnAagKLHqu3/AInX+Is/0YEHg7GJaLVT6neSvQV1z4KogF1wJphHnnoc2W7XJ7cEv69+jDsG2VQotzVo7+fpWRGC1AgMBAAECggEAPSCn9SNrPhlzVN6u+AmfzsaNBDDoXCkKw3fWkgP4OGT1gWVyxHVIJyOLlQ9U2J8q9BXAfaSzu9IMb/dJdRe1wBPxtnv04kLStjolBFC0Ix1GMIrDXcGUZr5NxZFrGyDnGE69owNHZMx/dONU3fyNPtl9ouHqIQtNqGgCc7LXvqZZGaOLopPUt8VRhRl5txaQI+cUq3C4Q8ms0tKK7TlV1i0DTxf+GV/bPJ2ANm3eTdQF1g1gN2iOm6Lux+6YzvCpt4qGEtOnReu1FLd7piA2wcrhGLWKGuhXSa3tpTlSQlmLU8Memf9SDI8TuO4vTgMjkw8Fzi8J1ZP+VlI74oO7LQKBgQDNJY75ODKF8FQZwJjeo4kFhQTj3duVg5bkTklw4eUW0LQmyKHMHZMhiRPzFvjeGTguS3sBBIx2S6r2SJSzJalpDpV0j1Qeby10FkclUjPIO7gUkzXG9Hv3LvhginHK6n4O2wutKe4eRLPTMO8qdShUGpMitIqHOQSTjJkVzvKgkwKBgQDCXKccGsZrYF8lmV50/1WmrB5yLqYiZDG9NQjd0np2PZWfvszR536o5SP8rG+InH4TaGsvgWgq4fPiRA8EtZ+19hj9yLW9IGWTS1UPIeQ1Oog6bsmVe/YNm/E1pvKavH5DNMT9Ed86akO0scxVfvO9yylpOqdjK5ZEBP+CywXulwKBgG3r7gwD3K5/89BIrqC9J7JZcCFYw0v90mBKwndF0ybCdYVCg8+HGUsi1Bmw+XCoOr4zm5kUAt9v9A87HNJRH9E3C0YFdqFIGSbWuRB6V1y3Aw+jQXF1lub/t/6isA52T01OeZcznG+DiIdk9QHe/Njz1FsIOiHyn00gTPauiLsZAoGAaL60FJJdcoq6XDH+VMEycKN7uP9o60niAFzvjVQcSVLBKxkRmuHOQclTjp2DcjUcQOtaMHzmHY4t+DfDfD9BdjfNmh+ryeQGuc20ZnZWXVVRC2SfYN8waH8tDEQPpNKGnUN4EgaqrfmMyXm0bDMBurwdcid5BBn+XmPvK5aseLsCgYEAxQChIvZbHi83/UZIUIIuCXNJsOgsXCwARvUOdOomoWJuvKYRV1JhaSDShvTKGNkAlKj4RuwkQfSJffErmT1wCGIn5+UzHsHfrFgMmIUuAlH+IP5bZQJbYU83v12PmZoO8SPPRDR3AZIMPdNHaouxoMNu2+fEwKcDqV/WuD4UlMY= -----END PRIVATE KEY-----';

            try {

                const signature = KJUR.jws.JWS.sign('RS256', header, payload, privateKey);
                return signature;

            } catch (e) {
                console.log("Error al generar el token signature :: ", e)
            }
        }));
    })))
}


function returnValue (body) {

    let signature = "initial";

    loadLibrary("../libraries/crypto-js.min.js", (() => {

        loadLibrary("../libraries/jsrsasign-all-min.js", (() => {

            const idempotentReference = JSON.parse(body).idempotentReference;
            const hash = CryptoJS.SHA256(body);
            const hashEncode = CryptoJS.enc.Base64.stringify(hash);
        
            console.log("Encode : ", hashEncode);

            const header = {
                'typ': 'JWT',
                'alg': 'RS256',
                'kid': 'mx_private_key_name'
            };
            
            const payload = {
                'alg': 'SHA256',
                'iss': 'value',
                'hd': hashEncode,
                'nonce': idempotentReference,
                'nbf': KJUR.jws.IntDate.get('now'),
                'iat': KJUR.jws.IntDate.get('now'),
                'exp': KJUR.jws.IntDate.get('now + 1month'),
                'jti': self.crypto.randomUUID()
            };

            const privateKey = '-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbwLXCQ/uEMS6NnF6KVQRA/xKCis82Fp9P5fu9GgJpiHGvq1JmTAbaEPeOU5BoMAx0I1vPXKA/cB9kSw84yxGQmnzaqcVwYDwgVfI6zJ4NF5yHQBD3CrN0fIlZep3/qWQ/jtWWhxXoQExz1yF3CqHPKIDf5bHHgFmxcq0yzYXkYKsl2rAiNSQcdR0ycWDCg1YsVTxqTBvbqRDzg8+aXmgx9UUP4VO29U+8NQ73Ew1MpE7hldoZfvdF8OHfuwaCnAagKLHqu3/AInX+Is/0YEHg7GJaLVT6neSvQV1z4KogF1wJphHnnoc2W7XJ7cEv69+jDsG2VQotzVo7+fpWRGC1AgMBAAECggEAPSCn9SNrPhlzVN6u+AmfzsaNBDDoXCkKw3fWkgP4OGT1gWVyxHVIJyOLlQ9U2J8q9BXAfaSzu9IMb/dJdRe1wBPxtnv04kLStjolBFC0Ix1GMIrDXcGUZr5NxZFrGyDnGE69owNHZMx/dONU3fyNPtl9ouHqIQtNqGgCc7LXvqZZGaOLopPUt8VRhRl5txaQI+cUq3C4Q8ms0tKK7TlV1i0DTxf+GV/bPJ2ANm3eTdQF1g1gN2iOm6Lux+6YzvCpt4qGEtOnReu1FLd7piA2wcrhGLWKGuhXSa3tpTlSQlmLU8Memf9SDI8TuO4vTgMjkw8Fzi8J1ZP+VlI74oO7LQKBgQDNJY75ODKF8FQZwJjeo4kFhQTj3duVg5bkTklw4eUW0LQmyKHMHZMhiRPzFvjeGTguS3sBBIx2S6r2SJSzJalpDpV0j1Qeby10FkclUjPIO7gUkzXG9Hv3LvhginHK6n4O2wutKe4eRLPTMO8qdShUGpMitIqHOQSTjJkVzvKgkwKBgQDCXKccGsZrYF8lmV50/1WmrB5yLqYiZDG9NQjd0np2PZWfvszR536o5SP8rG+InH4TaGsvgWgq4fPiRA8EtZ+19hj9yLW9IGWTS1UPIeQ1Oog6bsmVe/YNm/E1pvKavH5DNMT9Ed86akO0scxVfvO9yylpOqdjK5ZEBP+CywXulwKBgG3r7gwD3K5/89BIrqC9J7JZcCFYw0v90mBKwndF0ybCdYVCg8+HGUsi1Bmw+XCoOr4zm5kUAt9v9A87HNJRH9E3C0YFdqFIGSbWuRB6V1y3Aw+jQXF1lub/t/6isA52T01OeZcznG+DiIdk9QHe/Njz1FsIOiHyn00gTPauiLsZAoGAaL60FJJdcoq6XDH+VMEycKN7uP9o60niAFzvjVQcSVLBKxkRmuHOQclTjp2DcjUcQOtaMHzmHY4t+DfDfD9BdjfNmh+ryeQGuc20ZnZWXVVRC2SfYN8waH8tDEQPpNKGnUN4EgaqrfmMyXm0bDMBurwdcid5BBn+XmPvK5aseLsCgYEAxQChIvZbHi83/UZIUIIuCXNJsOgsXCwARvUOdOomoWJuvKYRV1JhaSDShvTKGNkAlKj4RuwkQfSJffErmT1wCGIn5+UzHsHfrFgMmIUuAlH+IP5bZQJbYU83v12PmZoO8SPPRDR3AZIMPdNHaouxoMNu2+fEwKcDqV/WuD4UlMY= -----END PRIVATE KEY-----';

            try {

                signature = KJUR.jws.JWS.sign('RS256', header, payload, privateKey);
                return signature;

            } catch (e) {
                console.log("Error al generar el token signature :: ", e)
            }
        }));

        return signature;
    }));

    return signature;
}


//Ejemplo body y llamado
const body = "{\r\n    \"idempotentReference\": \"REF00001\",\r\n    \"productId\": \"any\"\r\n}"
//console.log("TOKEN FIRMADO :: ", getJWTSignature(body));

console.log(returnValue(body))