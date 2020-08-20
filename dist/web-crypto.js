!function(t,r){"object"==typeof exports&&"object"==typeof module?module.exports=r():"function"==typeof define&&define.amd?define("WebCrypto",[],r):"object"==typeof exports?exports.WebCrypto=r():t.WebCrypto=r()}(window,(function(){return function(t){var r={};function e(n){if(r[n])return r[n].exports;var i=r[n]={i:n,l:!1,exports:{}};return t[n].call(i.exports,i,i.exports,e),i.l=!0,i.exports}return e.m=t,e.c=r,e.d=function(t,r,n){e.o(t,r)||Object.defineProperty(t,r,{enumerable:!0,get:n})},e.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},e.t=function(t,r){if(1&r&&(t=e(t)),8&r)return t;if(4&r&&"object"==typeof t&&t&&t.__esModule)return t;var n=Object.create(null);if(e.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:t}),2&r&&"string"!=typeof t)for(var i in t)e.d(n,i,function(r){return t[r]}.bind(null,i));return n},e.n=function(t){var r=t&&t.__esModule?function(){return t.default}:function(){return t};return e.d(r,"a",r),r},e.o=function(t,r){return Object.prototype.hasOwnProperty.call(t,r)},e.p="",e(e.s=0)}([function(t,r,e){"use strict";(function(t){var e=this&&this.__awaiter||function(t,r,e,n){return new(e||(e=Promise))((function(i,o){function u(t){try{s(n.next(t))}catch(t){o(t)}}function a(t){try{s(n.throw(t))}catch(t){o(t)}}function s(t){var r;t.done?i(t.value):(r=t.value,r instanceof e?r:new e((function(t){t(r)}))).then(u,a)}s((n=n.apply(t,r||[])).next())}))},n=this&&this.__generator||function(t,r){var e,n,i,o,u={label:0,sent:function(){if(1&i[0])throw i[1];return i[1]},trys:[],ops:[]};return o={next:a(0),throw:a(1),return:a(2)},"function"==typeof Symbol&&(o[Symbol.iterator]=function(){return this}),o;function a(o){return function(a){return function(o){if(e)throw new TypeError("Generator is already executing.");for(;u;)try{if(e=1,n&&(i=2&o[0]?n.return:o[0]?n.throw||((i=n.return)&&i.call(n),0):n.next)&&!(i=i.call(n,o[1])).done)return i;switch(n=0,i&&(o=[2&o[0],i.value]),o[0]){case 0:case 1:i=o;break;case 4:return u.label++,{value:o[1],done:!1};case 5:u.label++,n=o[1],o=[0];continue;case 7:o=u.ops.pop(),u.trys.pop();continue;default:if(!(i=u.trys,(i=i.length>0&&i[i.length-1])||6!==o[0]&&2!==o[0])){u=0;continue}if(3===o[0]&&(!i||o[1]>i[0]&&o[1]<i[3])){u.label=o[1];break}if(6===o[0]&&u.label<i[1]){u.label=i[1],i=o;break}if(i&&u.label<i[2]){u.label=i[2],u.ops.push(o);break}i[2]&&u.ops.pop(),u.trys.pop();continue}o=r.call(t,u)}catch(t){o=[6,t],n=0}finally{e=i=0}if(5&o[0])throw o[1];return{value:o[0]?o[1]:void 0,done:!0}}([o,a])}}};Object.defineProperty(r,"__esModule",{value:!0}),r._genRandomBufferAsStr=r._genRandomBuffer=r.updatePassphraseKey=r.decryptMasterKey=r.genEncryptedMasterKey=r.decryptBuffer=r.encryptBuffer=r.decrypt=r.encrypt=r.exportKey=r.importKey=r.genAESKey=r.verify=r.sign=r.exportPrivateKey=r.exportPublicKey=r.importPrivateKey=r.importPublicKey=r.genKeyPair=r.hash=r.genId=void 0;var i=function(t){if(!t.type||"secret"!==t.type)throw new Error("Invalid key type")},o=function(r){void 0===r&&(r=16);var e=window.crypto.getRandomValues(new Uint8Array(r));return t.from(e)},u=function(t,r){return void 0===t&&(t=16),void 0===r&&(r="hex"),r&&a(r),o(t).toString(r)},a=function(t){if("hex"!==t&&"base64"!==t)throw new Error("Invalid encoding")};r.genId=function(t){return void 0===t&&(t=32),u(Math.floor(t/2))};r.hash=function(r,i,o){return void 0===i&&(i="hex"),void 0===o&&(o="SHA-256"),e(void 0,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return[4,window.crypto.subtle.digest({name:o},"string"==typeof r?t.from(r):r)];case 1:return e=n.sent(),[2,t.from(e).toString(i)]}}))}))};r.genKeyPair=function(t,r){return void 0===t&&(t=!0),void 0===r&&(r="P-256"),window.crypto.subtle.generateKey({name:"ECDSA",namedCurve:r},t,["sign","verify"])},r.importPublicKey=function(r,e,n){return void 0===e&&(e="P-256"),void 0===n&&(n="base64"),window.crypto.subtle.importKey("spki","string"==typeof r?t.from(r,n):r,{name:"ECDSA",namedCurve:e},!0,["verify"])},r.importPrivateKey=function(r,e,n){return void 0===e&&(e="P-256"),void 0===n&&(n="base64"),window.crypto.subtle.importKey("pkcs8","string"==typeof r?t.from(r,n):r,{name:"ECDSA",namedCurve:e},!0,["sign"])},r.exportPublicKey=function(r,i){return void 0===i&&(i="base64"),e(this,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return[4,window.crypto.subtle.exportKey("spki",r)];case 1:return e=n.sent(),[2,"raw"===i?new Uint8Array(e):t.from(e).toString(i)]}}))}))},r.exportPrivateKey=function(r,i){return void 0===i&&(i="base64"),e(this,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return[4,window.crypto.subtle.exportKey("pkcs8",r)];case 1:return e=n.sent(),[2,"raw"===i?new Uint8Array(e):t.from(e).toString(i)]}}))}))};r.sign=function(r,i,o,u){return void 0===o&&(o="base64"),void 0===u&&(u="SHA-256"),e(void 0,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return[4,window.crypto.subtle.sign({name:"ECDSA",hash:{name:u}},r,t.from(JSON.stringify(i)))];case 1:return e=n.sent(),[2,"raw"===o?new Uint8Array(e):t.from(e).toString(o)]}}))}))};r.verify=function(r,i,o,u,a){return void 0===u&&(u="base64"),void 0===a&&(a="SHA-256"),e(void 0,void 0,void 0,(function(){return n(this,(function(e){return[2,window.crypto.subtle.verify({name:"ECDSA",hash:{name:a}},r,t.from(o,u),t.from(JSON.stringify(i)))]}))}))};r.genAESKey=function(t,r,e){return void 0===t&&(t=!0),void 0===r&&(r="AES-GCM"),void 0===e&&(e=128),window.crypto.subtle.generateKey({name:r,length:e},t,["decrypt","encrypt"])};var s=function(r,e,n){void 0===e&&(e="raw"),void 0===n&&(n="AES-GCM");var i="raw"===e?t.from(r,"base64"):r;return window.crypto.subtle.importKey(e,i,{name:n},!0,["encrypt","decrypt"])};r.importKey=s;var f=function(t,r){return void 0===r&&(r="raw"),e(void 0,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return[4,window.crypto.subtle.exportKey(r,t)];case 1:return e=n.sent(),[2,"raw"===r?new Uint8Array(e):e]}}))}))};r.exportKey=f;var h=function(t,r,i){return e(void 0,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return[4,window.crypto.subtle.encrypt(i,t,r)];case 1:return e=n.sent(),[2,new Uint8Array(e)]}}))}))};r.encryptBuffer=h;var c=function(t,r,i){return e(void 0,void 0,void 0,(function(){var e;return n(this,(function(n){switch(n.label){case 0:return n.trys.push([0,2,,3]),[4,window.crypto.subtle.decrypt(i,t,r)];case 1:return e=n.sent(),[2,new Uint8Array(e)];case 2:if("Unsupported state or unable to authenticate data"===n.sent().message)throw new Error("Unable to decrypt data");return[3,3];case 3:return[2]}}))}))};r.decryptBuffer=c;var l=function(r,u,a){return void 0===a&&(a="hex"),e(void 0,void 0,void 0,(function(){var e,s,f;return n(this,(function(n){switch(n.label){case 0:return i(r),e={iv:o("AES-GCM"===r.algorithm.name?12:16),plaintext:t.from(JSON.stringify(u))},s={name:r.algorithm.name,iv:e.iv},[4,h(r,e.plaintext,s)];case 1:return f=n.sent(),[2,{ciphertext:t.from(f).toString(a),iv:t.from(e.iv).toString(a)}]}}))}))};r.encrypt=l;var p=function(r,o,u){return void 0===u&&(u="hex"),e(void 0,void 0,void 0,(function(){var e,a,s;return n(this,(function(n){switch(n.label){case 0:i(r),e={ciphertext:t.from(Object.prototype.hasOwnProperty.call(o,"ciphertext")?o.ciphertext:"",u),iv:Object.prototype.hasOwnProperty.call(o,"iv")?t.from(o.iv,u):""},a={name:r.algorithm.name,iv:e.iv},n.label=1;case 1:return n.trys.push([1,3,,4]),[4,c(r,e.ciphertext,a)];case 2:if(void 0===(s=n.sent()))throw new Error;return[2,JSON.parse(t.from(s).toString())];case 3:throw n.sent(),new Error("Unable to decrypt data");case 4:return[2]}}))}))};r.decrypt=p;var y=function(r,i,o,u){return e(void 0,void 0,void 0,(function(){var e,a;return n(this,(function(n){switch(n.label){case 0:return o<1e4&&console.warn("Less than 10000 :("),[4,window.crypto.subtle.importKey("raw","string"==typeof r?t.from(r):r,"PBKDF2",!1,["deriveBits","deriveKey"])];case 1:return e=n.sent(),[4,window.crypto.subtle.deriveBits({name:"PBKDF2",salt:i||new Uint8Array([]),iterations:o||1e5,hash:u||"SHA-256"},e,128)];case 2:return a=n.sent(),[2,new Uint8Array(a)]}}))}))},d=function(r,i,u,a){return void 0===i&&(i=o(16)),void 0===u&&(u=1e5),void 0===a&&(a="SHA-256"),e(void 0,void 0,void 0,(function(){var e,o;return n(this,(function(n){switch(n.label){case 0:return function(t){if("string"!=typeof t||""===t)throw new Error("Not a valid value")}(r),[4,y(r,i,u,a)];case 1:return e=n.sent(),[4,s(e)];case 2:return o=n.sent(),[2,{derivationParams:{salt:t.from(i).toString("hex"),iterations:u,hashAlgo:a},key:o}]}}))}))};r.genEncryptedMasterKey=function(t,r,i,o){return e(void 0,void 0,void 0,(function(){var e,a,s;return n(this,(function(n){switch(n.label){case 0:return[4,d(t,r,i,o)];case 1:return e=n.sent(),a=u(32,"hex"),[4,l(e.key,a)];case 2:return s=n.sent(),[2,{derivationParams:e.derivationParams,encryptedMasterKey:s}]}}))}))};r.updatePassphraseKey=function(r,i,o,u,a,s){return e(void 0,void 0,void 0,(function(){var e,h,c,p,y,v;return n(this,(function(n){switch(n.label){case 0:return[4,g(r,o)];case 1:return e=n.sent(),[4,d(i,u,a,s)];case 2:return h=n.sent(),y=(p=t).from,[4,f(e)];case 3:return c=y.apply(p,[n.sent()]).toString("hex"),[4,l(h.key,c)];case 4:return v=n.sent(),[2,{derivationParams:h.derivationParams,encryptedMasterKey:v}]}}))}))};var g=function(r,i){return e(void 0,void 0,void 0,(function(){var e,o,u,a,f,h,c,l,d,g;return n(this,(function(n){switch(n.label){case 0:if(!i.encryptedMasterKey||!i.derivationParams)throw new Error("Missing properties from master key");return e=i.derivationParams,o=i.encryptedMasterKey,u=e.salt,a=e.iterations,f=e.hashAlgo,h="string"==typeof u?t.from(u,"hex"):u,[4,y(r,h,a,f)];case 1:return c=n.sent(),[4,s(c)];case 2:l=n.sent(),n.label=3;case 3:return n.trys.push([3,5,,6]),[4,p(l,o)];case 4:return d=n.sent(),g=t.from(d,"hex"),[2,window.crypto.subtle.importKey("raw",g,{name:"AES-GCM"},!0,["encrypt","decrypt"])];case 5:throw n.sent(),new Error("Wrong passphrase");case 6:return[2]}}))}))};r.decryptMasterKey=g;var v=o;r._genRandomBuffer=v;var w=u;r._genRandomBufferAsStr=w}).call(this,e(1).Buffer)},function(t,r,e){"use strict";(function(t){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
var n=e(3),i=e(4),o=e(5);function u(){return s.TYPED_ARRAY_SUPPORT?2147483647:1073741823}function a(t,r){if(u()<r)throw new RangeError("Invalid typed array length");return s.TYPED_ARRAY_SUPPORT?(t=new Uint8Array(r)).__proto__=s.prototype:(null===t&&(t=new s(r)),t.length=r),t}function s(t,r,e){if(!(s.TYPED_ARRAY_SUPPORT||this instanceof s))return new s(t,r,e);if("number"==typeof t){if("string"==typeof r)throw new Error("If encoding is specified then the first argument must be a string");return c(this,t)}return f(this,t,r,e)}function f(t,r,e,n){if("number"==typeof r)throw new TypeError('"value" argument must not be a number');return"undefined"!=typeof ArrayBuffer&&r instanceof ArrayBuffer?function(t,r,e,n){if(r.byteLength,e<0||r.byteLength<e)throw new RangeError("'offset' is out of bounds");if(r.byteLength<e+(n||0))throw new RangeError("'length' is out of bounds");r=void 0===e&&void 0===n?new Uint8Array(r):void 0===n?new Uint8Array(r,e):new Uint8Array(r,e,n);s.TYPED_ARRAY_SUPPORT?(t=r).__proto__=s.prototype:t=l(t,r);return t}(t,r,e,n):"string"==typeof r?function(t,r,e){"string"==typeof e&&""!==e||(e="utf8");if(!s.isEncoding(e))throw new TypeError('"encoding" must be a valid string encoding');var n=0|y(r,e),i=(t=a(t,n)).write(r,e);i!==n&&(t=t.slice(0,i));return t}(t,r,e):function(t,r){if(s.isBuffer(r)){var e=0|p(r.length);return 0===(t=a(t,e)).length||r.copy(t,0,0,e),t}if(r){if("undefined"!=typeof ArrayBuffer&&r.buffer instanceof ArrayBuffer||"length"in r)return"number"!=typeof r.length||(n=r.length)!=n?a(t,0):l(t,r);if("Buffer"===r.type&&o(r.data))return l(t,r.data)}var n;throw new TypeError("First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.")}(t,r)}function h(t){if("number"!=typeof t)throw new TypeError('"size" argument must be a number');if(t<0)throw new RangeError('"size" argument must not be negative')}function c(t,r){if(h(r),t=a(t,r<0?0:0|p(r)),!s.TYPED_ARRAY_SUPPORT)for(var e=0;e<r;++e)t[e]=0;return t}function l(t,r){var e=r.length<0?0:0|p(r.length);t=a(t,e);for(var n=0;n<e;n+=1)t[n]=255&r[n];return t}function p(t){if(t>=u())throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+u().toString(16)+" bytes");return 0|t}function y(t,r){if(s.isBuffer(t))return t.length;if("undefined"!=typeof ArrayBuffer&&"function"==typeof ArrayBuffer.isView&&(ArrayBuffer.isView(t)||t instanceof ArrayBuffer))return t.byteLength;"string"!=typeof t&&(t=""+t);var e=t.length;if(0===e)return 0;for(var n=!1;;)switch(r){case"ascii":case"latin1":case"binary":return e;case"utf8":case"utf-8":case void 0:return N(t).length;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return 2*e;case"hex":return e>>>1;case"base64":return j(t).length;default:if(n)return N(t).length;r=(""+r).toLowerCase(),n=!0}}function d(t,r,e){var n=!1;if((void 0===r||r<0)&&(r=0),r>this.length)return"";if((void 0===e||e>this.length)&&(e=this.length),e<=0)return"";if((e>>>=0)<=(r>>>=0))return"";for(t||(t="utf8");;)switch(t){case"hex":return T(this,r,e);case"utf8":case"utf-8":return S(this,r,e);case"ascii":return B(this,r,e);case"latin1":case"binary":return U(this,r,e);case"base64":return R(this,r,e);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return x(this,r,e);default:if(n)throw new TypeError("Unknown encoding: "+t);t=(t+"").toLowerCase(),n=!0}}function g(t,r,e){var n=t[r];t[r]=t[e],t[e]=n}function v(t,r,e,n,i){if(0===t.length)return-1;if("string"==typeof e?(n=e,e=0):e>2147483647?e=2147483647:e<-2147483648&&(e=-2147483648),e=+e,isNaN(e)&&(e=i?0:t.length-1),e<0&&(e=t.length+e),e>=t.length){if(i)return-1;e=t.length-1}else if(e<0){if(!i)return-1;e=0}if("string"==typeof r&&(r=s.from(r,n)),s.isBuffer(r))return 0===r.length?-1:w(t,r,e,n,i);if("number"==typeof r)return r&=255,s.TYPED_ARRAY_SUPPORT&&"function"==typeof Uint8Array.prototype.indexOf?i?Uint8Array.prototype.indexOf.call(t,r,e):Uint8Array.prototype.lastIndexOf.call(t,r,e):w(t,[r],e,n,i);throw new TypeError("val must be string, number or Buffer")}function w(t,r,e,n,i){var o,u=1,a=t.length,s=r.length;if(void 0!==n&&("ucs2"===(n=String(n).toLowerCase())||"ucs-2"===n||"utf16le"===n||"utf-16le"===n)){if(t.length<2||r.length<2)return-1;u=2,a/=2,s/=2,e/=2}function f(t,r){return 1===u?t[r]:t.readUInt16BE(r*u)}if(i){var h=-1;for(o=e;o<a;o++)if(f(t,o)===f(r,-1===h?0:o-h)){if(-1===h&&(h=o),o-h+1===s)return h*u}else-1!==h&&(o-=o-h),h=-1}else for(e+s>a&&(e=a-s),o=e;o>=0;o--){for(var c=!0,l=0;l<s;l++)if(f(t,o+l)!==f(r,l)){c=!1;break}if(c)return o}return-1}function b(t,r,e,n){e=Number(e)||0;var i=t.length-e;n?(n=Number(n))>i&&(n=i):n=i;var o=r.length;if(o%2!=0)throw new TypeError("Invalid hex string");n>o/2&&(n=o/2);for(var u=0;u<n;++u){var a=parseInt(r.substr(2*u,2),16);if(isNaN(a))return u;t[e+u]=a}return u}function m(t,r,e,n){return F(N(r,t.length-e),t,e,n)}function A(t,r,e,n){return F(function(t){for(var r=[],e=0;e<t.length;++e)r.push(255&t.charCodeAt(e));return r}(r),t,e,n)}function E(t,r,e,n){return A(t,r,e,n)}function P(t,r,e,n){return F(j(r),t,e,n)}function _(t,r,e,n){return F(function(t,r){for(var e,n,i,o=[],u=0;u<t.length&&!((r-=2)<0);++u)e=t.charCodeAt(u),n=e>>8,i=e%256,o.push(i),o.push(n);return o}(r,t.length-e),t,e,n)}function R(t,r,e){return 0===r&&e===t.length?n.fromByteArray(t):n.fromByteArray(t.slice(r,e))}function S(t,r,e){e=Math.min(t.length,e);for(var n=[],i=r;i<e;){var o,u,a,s,f=t[i],h=null,c=f>239?4:f>223?3:f>191?2:1;if(i+c<=e)switch(c){case 1:f<128&&(h=f);break;case 2:128==(192&(o=t[i+1]))&&(s=(31&f)<<6|63&o)>127&&(h=s);break;case 3:o=t[i+1],u=t[i+2],128==(192&o)&&128==(192&u)&&(s=(15&f)<<12|(63&o)<<6|63&u)>2047&&(s<55296||s>57343)&&(h=s);break;case 4:o=t[i+1],u=t[i+2],a=t[i+3],128==(192&o)&&128==(192&u)&&128==(192&a)&&(s=(15&f)<<18|(63&o)<<12|(63&u)<<6|63&a)>65535&&s<1114112&&(h=s)}null===h?(h=65533,c=1):h>65535&&(h-=65536,n.push(h>>>10&1023|55296),h=56320|1023&h),n.push(h),i+=c}return function(t){var r=t.length;if(r<=4096)return String.fromCharCode.apply(String,t);var e="",n=0;for(;n<r;)e+=String.fromCharCode.apply(String,t.slice(n,n+=4096));return e}(n)}r.Buffer=s,r.SlowBuffer=function(t){+t!=t&&(t=0);return s.alloc(+t)},r.INSPECT_MAX_BYTES=50,s.TYPED_ARRAY_SUPPORT=void 0!==t.TYPED_ARRAY_SUPPORT?t.TYPED_ARRAY_SUPPORT:function(){try{var t=new Uint8Array(1);return t.__proto__={__proto__:Uint8Array.prototype,foo:function(){return 42}},42===t.foo()&&"function"==typeof t.subarray&&0===t.subarray(1,1).byteLength}catch(t){return!1}}(),r.kMaxLength=u(),s.poolSize=8192,s._augment=function(t){return t.__proto__=s.prototype,t},s.from=function(t,r,e){return f(null,t,r,e)},s.TYPED_ARRAY_SUPPORT&&(s.prototype.__proto__=Uint8Array.prototype,s.__proto__=Uint8Array,"undefined"!=typeof Symbol&&Symbol.species&&s[Symbol.species]===s&&Object.defineProperty(s,Symbol.species,{value:null,configurable:!0})),s.alloc=function(t,r,e){return function(t,r,e,n){return h(r),r<=0?a(t,r):void 0!==e?"string"==typeof n?a(t,r).fill(e,n):a(t,r).fill(e):a(t,r)}(null,t,r,e)},s.allocUnsafe=function(t){return c(null,t)},s.allocUnsafeSlow=function(t){return c(null,t)},s.isBuffer=function(t){return!(null==t||!t._isBuffer)},s.compare=function(t,r){if(!s.isBuffer(t)||!s.isBuffer(r))throw new TypeError("Arguments must be Buffers");if(t===r)return 0;for(var e=t.length,n=r.length,i=0,o=Math.min(e,n);i<o;++i)if(t[i]!==r[i]){e=t[i],n=r[i];break}return e<n?-1:n<e?1:0},s.isEncoding=function(t){switch(String(t).toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"latin1":case"binary":case"base64":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return!0;default:return!1}},s.concat=function(t,r){if(!o(t))throw new TypeError('"list" argument must be an Array of Buffers');if(0===t.length)return s.alloc(0);var e;if(void 0===r)for(r=0,e=0;e<t.length;++e)r+=t[e].length;var n=s.allocUnsafe(r),i=0;for(e=0;e<t.length;++e){var u=t[e];if(!s.isBuffer(u))throw new TypeError('"list" argument must be an Array of Buffers');u.copy(n,i),i+=u.length}return n},s.byteLength=y,s.prototype._isBuffer=!0,s.prototype.swap16=function(){var t=this.length;if(t%2!=0)throw new RangeError("Buffer size must be a multiple of 16-bits");for(var r=0;r<t;r+=2)g(this,r,r+1);return this},s.prototype.swap32=function(){var t=this.length;if(t%4!=0)throw new RangeError("Buffer size must be a multiple of 32-bits");for(var r=0;r<t;r+=4)g(this,r,r+3),g(this,r+1,r+2);return this},s.prototype.swap64=function(){var t=this.length;if(t%8!=0)throw new RangeError("Buffer size must be a multiple of 64-bits");for(var r=0;r<t;r+=8)g(this,r,r+7),g(this,r+1,r+6),g(this,r+2,r+5),g(this,r+3,r+4);return this},s.prototype.toString=function(){var t=0|this.length;return 0===t?"":0===arguments.length?S(this,0,t):d.apply(this,arguments)},s.prototype.equals=function(t){if(!s.isBuffer(t))throw new TypeError("Argument must be a Buffer");return this===t||0===s.compare(this,t)},s.prototype.inspect=function(){var t="",e=r.INSPECT_MAX_BYTES;return this.length>0&&(t=this.toString("hex",0,e).match(/.{2}/g).join(" "),this.length>e&&(t+=" ... ")),"<Buffer "+t+">"},s.prototype.compare=function(t,r,e,n,i){if(!s.isBuffer(t))throw new TypeError("Argument must be a Buffer");if(void 0===r&&(r=0),void 0===e&&(e=t?t.length:0),void 0===n&&(n=0),void 0===i&&(i=this.length),r<0||e>t.length||n<0||i>this.length)throw new RangeError("out of range index");if(n>=i&&r>=e)return 0;if(n>=i)return-1;if(r>=e)return 1;if(this===t)return 0;for(var o=(i>>>=0)-(n>>>=0),u=(e>>>=0)-(r>>>=0),a=Math.min(o,u),f=this.slice(n,i),h=t.slice(r,e),c=0;c<a;++c)if(f[c]!==h[c]){o=f[c],u=h[c];break}return o<u?-1:u<o?1:0},s.prototype.includes=function(t,r,e){return-1!==this.indexOf(t,r,e)},s.prototype.indexOf=function(t,r,e){return v(this,t,r,e,!0)},s.prototype.lastIndexOf=function(t,r,e){return v(this,t,r,e,!1)},s.prototype.write=function(t,r,e,n){if(void 0===r)n="utf8",e=this.length,r=0;else if(void 0===e&&"string"==typeof r)n=r,e=this.length,r=0;else{if(!isFinite(r))throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");r|=0,isFinite(e)?(e|=0,void 0===n&&(n="utf8")):(n=e,e=void 0)}var i=this.length-r;if((void 0===e||e>i)&&(e=i),t.length>0&&(e<0||r<0)||r>this.length)throw new RangeError("Attempt to write outside buffer bounds");n||(n="utf8");for(var o=!1;;)switch(n){case"hex":return b(this,t,r,e);case"utf8":case"utf-8":return m(this,t,r,e);case"ascii":return A(this,t,r,e);case"latin1":case"binary":return E(this,t,r,e);case"base64":return P(this,t,r,e);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return _(this,t,r,e);default:if(o)throw new TypeError("Unknown encoding: "+n);n=(""+n).toLowerCase(),o=!0}},s.prototype.toJSON=function(){return{type:"Buffer",data:Array.prototype.slice.call(this._arr||this,0)}};function B(t,r,e){var n="";e=Math.min(t.length,e);for(var i=r;i<e;++i)n+=String.fromCharCode(127&t[i]);return n}function U(t,r,e){var n="";e=Math.min(t.length,e);for(var i=r;i<e;++i)n+=String.fromCharCode(t[i]);return n}function T(t,r,e){var n=t.length;(!r||r<0)&&(r=0),(!e||e<0||e>n)&&(e=n);for(var i="",o=r;o<e;++o)i+=k(t[o]);return i}function x(t,r,e){for(var n=t.slice(r,e),i="",o=0;o<n.length;o+=2)i+=String.fromCharCode(n[o]+256*n[o+1]);return i}function M(t,r,e){if(t%1!=0||t<0)throw new RangeError("offset is not uint");if(t+r>e)throw new RangeError("Trying to access beyond buffer length")}function C(t,r,e,n,i,o){if(!s.isBuffer(t))throw new TypeError('"buffer" argument must be a Buffer instance');if(r>i||r<o)throw new RangeError('"value" argument is out of bounds');if(e+n>t.length)throw new RangeError("Index out of range")}function O(t,r,e,n){r<0&&(r=65535+r+1);for(var i=0,o=Math.min(t.length-e,2);i<o;++i)t[e+i]=(r&255<<8*(n?i:1-i))>>>8*(n?i:1-i)}function I(t,r,e,n){r<0&&(r=4294967295+r+1);for(var i=0,o=Math.min(t.length-e,4);i<o;++i)t[e+i]=r>>>8*(n?i:3-i)&255}function Y(t,r,e,n,i,o){if(e+n>t.length)throw new RangeError("Index out of range");if(e<0)throw new RangeError("Index out of range")}function K(t,r,e,n,o){return o||Y(t,0,e,4),i.write(t,r,e,n,23,4),e+4}function D(t,r,e,n,o){return o||Y(t,0,e,8),i.write(t,r,e,n,52,8),e+8}s.prototype.slice=function(t,r){var e,n=this.length;if((t=~~t)<0?(t+=n)<0&&(t=0):t>n&&(t=n),(r=void 0===r?n:~~r)<0?(r+=n)<0&&(r=0):r>n&&(r=n),r<t&&(r=t),s.TYPED_ARRAY_SUPPORT)(e=this.subarray(t,r)).__proto__=s.prototype;else{var i=r-t;e=new s(i,void 0);for(var o=0;o<i;++o)e[o]=this[o+t]}return e},s.prototype.readUIntLE=function(t,r,e){t|=0,r|=0,e||M(t,r,this.length);for(var n=this[t],i=1,o=0;++o<r&&(i*=256);)n+=this[t+o]*i;return n},s.prototype.readUIntBE=function(t,r,e){t|=0,r|=0,e||M(t,r,this.length);for(var n=this[t+--r],i=1;r>0&&(i*=256);)n+=this[t+--r]*i;return n},s.prototype.readUInt8=function(t,r){return r||M(t,1,this.length),this[t]},s.prototype.readUInt16LE=function(t,r){return r||M(t,2,this.length),this[t]|this[t+1]<<8},s.prototype.readUInt16BE=function(t,r){return r||M(t,2,this.length),this[t]<<8|this[t+1]},s.prototype.readUInt32LE=function(t,r){return r||M(t,4,this.length),(this[t]|this[t+1]<<8|this[t+2]<<16)+16777216*this[t+3]},s.prototype.readUInt32BE=function(t,r){return r||M(t,4,this.length),16777216*this[t]+(this[t+1]<<16|this[t+2]<<8|this[t+3])},s.prototype.readIntLE=function(t,r,e){t|=0,r|=0,e||M(t,r,this.length);for(var n=this[t],i=1,o=0;++o<r&&(i*=256);)n+=this[t+o]*i;return n>=(i*=128)&&(n-=Math.pow(2,8*r)),n},s.prototype.readIntBE=function(t,r,e){t|=0,r|=0,e||M(t,r,this.length);for(var n=r,i=1,o=this[t+--n];n>0&&(i*=256);)o+=this[t+--n]*i;return o>=(i*=128)&&(o-=Math.pow(2,8*r)),o},s.prototype.readInt8=function(t,r){return r||M(t,1,this.length),128&this[t]?-1*(255-this[t]+1):this[t]},s.prototype.readInt16LE=function(t,r){r||M(t,2,this.length);var e=this[t]|this[t+1]<<8;return 32768&e?4294901760|e:e},s.prototype.readInt16BE=function(t,r){r||M(t,2,this.length);var e=this[t+1]|this[t]<<8;return 32768&e?4294901760|e:e},s.prototype.readInt32LE=function(t,r){return r||M(t,4,this.length),this[t]|this[t+1]<<8|this[t+2]<<16|this[t+3]<<24},s.prototype.readInt32BE=function(t,r){return r||M(t,4,this.length),this[t]<<24|this[t+1]<<16|this[t+2]<<8|this[t+3]},s.prototype.readFloatLE=function(t,r){return r||M(t,4,this.length),i.read(this,t,!0,23,4)},s.prototype.readFloatBE=function(t,r){return r||M(t,4,this.length),i.read(this,t,!1,23,4)},s.prototype.readDoubleLE=function(t,r){return r||M(t,8,this.length),i.read(this,t,!0,52,8)},s.prototype.readDoubleBE=function(t,r){return r||M(t,8,this.length),i.read(this,t,!1,52,8)},s.prototype.writeUIntLE=function(t,r,e,n){(t=+t,r|=0,e|=0,n)||C(this,t,r,e,Math.pow(2,8*e)-1,0);var i=1,o=0;for(this[r]=255&t;++o<e&&(i*=256);)this[r+o]=t/i&255;return r+e},s.prototype.writeUIntBE=function(t,r,e,n){(t=+t,r|=0,e|=0,n)||C(this,t,r,e,Math.pow(2,8*e)-1,0);var i=e-1,o=1;for(this[r+i]=255&t;--i>=0&&(o*=256);)this[r+i]=t/o&255;return r+e},s.prototype.writeUInt8=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,1,255,0),s.TYPED_ARRAY_SUPPORT||(t=Math.floor(t)),this[r]=255&t,r+1},s.prototype.writeUInt16LE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,2,65535,0),s.TYPED_ARRAY_SUPPORT?(this[r]=255&t,this[r+1]=t>>>8):O(this,t,r,!0),r+2},s.prototype.writeUInt16BE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,2,65535,0),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>8,this[r+1]=255&t):O(this,t,r,!1),r+2},s.prototype.writeUInt32LE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,4,4294967295,0),s.TYPED_ARRAY_SUPPORT?(this[r+3]=t>>>24,this[r+2]=t>>>16,this[r+1]=t>>>8,this[r]=255&t):I(this,t,r,!0),r+4},s.prototype.writeUInt32BE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,4,4294967295,0),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>24,this[r+1]=t>>>16,this[r+2]=t>>>8,this[r+3]=255&t):I(this,t,r,!1),r+4},s.prototype.writeIntLE=function(t,r,e,n){if(t=+t,r|=0,!n){var i=Math.pow(2,8*e-1);C(this,t,r,e,i-1,-i)}var o=0,u=1,a=0;for(this[r]=255&t;++o<e&&(u*=256);)t<0&&0===a&&0!==this[r+o-1]&&(a=1),this[r+o]=(t/u>>0)-a&255;return r+e},s.prototype.writeIntBE=function(t,r,e,n){if(t=+t,r|=0,!n){var i=Math.pow(2,8*e-1);C(this,t,r,e,i-1,-i)}var o=e-1,u=1,a=0;for(this[r+o]=255&t;--o>=0&&(u*=256);)t<0&&0===a&&0!==this[r+o+1]&&(a=1),this[r+o]=(t/u>>0)-a&255;return r+e},s.prototype.writeInt8=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,1,127,-128),s.TYPED_ARRAY_SUPPORT||(t=Math.floor(t)),t<0&&(t=255+t+1),this[r]=255&t,r+1},s.prototype.writeInt16LE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,2,32767,-32768),s.TYPED_ARRAY_SUPPORT?(this[r]=255&t,this[r+1]=t>>>8):O(this,t,r,!0),r+2},s.prototype.writeInt16BE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,2,32767,-32768),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>8,this[r+1]=255&t):O(this,t,r,!1),r+2},s.prototype.writeInt32LE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,4,2147483647,-2147483648),s.TYPED_ARRAY_SUPPORT?(this[r]=255&t,this[r+1]=t>>>8,this[r+2]=t>>>16,this[r+3]=t>>>24):I(this,t,r,!0),r+4},s.prototype.writeInt32BE=function(t,r,e){return t=+t,r|=0,e||C(this,t,r,4,2147483647,-2147483648),t<0&&(t=4294967295+t+1),s.TYPED_ARRAY_SUPPORT?(this[r]=t>>>24,this[r+1]=t>>>16,this[r+2]=t>>>8,this[r+3]=255&t):I(this,t,r,!1),r+4},s.prototype.writeFloatLE=function(t,r,e){return K(this,t,r,!0,e)},s.prototype.writeFloatBE=function(t,r,e){return K(this,t,r,!1,e)},s.prototype.writeDoubleLE=function(t,r,e){return D(this,t,r,!0,e)},s.prototype.writeDoubleBE=function(t,r,e){return D(this,t,r,!1,e)},s.prototype.copy=function(t,r,e,n){if(e||(e=0),n||0===n||(n=this.length),r>=t.length&&(r=t.length),r||(r=0),n>0&&n<e&&(n=e),n===e)return 0;if(0===t.length||0===this.length)return 0;if(r<0)throw new RangeError("targetStart out of bounds");if(e<0||e>=this.length)throw new RangeError("sourceStart out of bounds");if(n<0)throw new RangeError("sourceEnd out of bounds");n>this.length&&(n=this.length),t.length-r<n-e&&(n=t.length-r+e);var i,o=n-e;if(this===t&&e<r&&r<n)for(i=o-1;i>=0;--i)t[i+r]=this[i+e];else if(o<1e3||!s.TYPED_ARRAY_SUPPORT)for(i=0;i<o;++i)t[i+r]=this[i+e];else Uint8Array.prototype.set.call(t,this.subarray(e,e+o),r);return o},s.prototype.fill=function(t,r,e,n){if("string"==typeof t){if("string"==typeof r?(n=r,r=0,e=this.length):"string"==typeof e&&(n=e,e=this.length),1===t.length){var i=t.charCodeAt(0);i<256&&(t=i)}if(void 0!==n&&"string"!=typeof n)throw new TypeError("encoding must be a string");if("string"==typeof n&&!s.isEncoding(n))throw new TypeError("Unknown encoding: "+n)}else"number"==typeof t&&(t&=255);if(r<0||this.length<r||this.length<e)throw new RangeError("Out of range index");if(e<=r)return this;var o;if(r>>>=0,e=void 0===e?this.length:e>>>0,t||(t=0),"number"==typeof t)for(o=r;o<e;++o)this[o]=t;else{var u=s.isBuffer(t)?t:N(new s(t,n).toString()),a=u.length;for(o=0;o<e-r;++o)this[o+r]=u[o%a]}return this};var L=/[^+\/0-9A-Za-z-_]/g;function k(t){return t<16?"0"+t.toString(16):t.toString(16)}function N(t,r){var e;r=r||1/0;for(var n=t.length,i=null,o=[],u=0;u<n;++u){if((e=t.charCodeAt(u))>55295&&e<57344){if(!i){if(e>56319){(r-=3)>-1&&o.push(239,191,189);continue}if(u+1===n){(r-=3)>-1&&o.push(239,191,189);continue}i=e;continue}if(e<56320){(r-=3)>-1&&o.push(239,191,189),i=e;continue}e=65536+(i-55296<<10|e-56320)}else i&&(r-=3)>-1&&o.push(239,191,189);if(i=null,e<128){if((r-=1)<0)break;o.push(e)}else if(e<2048){if((r-=2)<0)break;o.push(e>>6|192,63&e|128)}else if(e<65536){if((r-=3)<0)break;o.push(e>>12|224,e>>6&63|128,63&e|128)}else{if(!(e<1114112))throw new Error("Invalid code point");if((r-=4)<0)break;o.push(e>>18|240,e>>12&63|128,e>>6&63|128,63&e|128)}}return o}function j(t){return n.toByteArray(function(t){if((t=function(t){return t.trim?t.trim():t.replace(/^\s+|\s+$/g,"")}(t).replace(L,"")).length<2)return"";for(;t.length%4!=0;)t+="=";return t}(t))}function F(t,r,e,n){for(var i=0;i<n&&!(i+e>=r.length||i>=t.length);++i)r[i+e]=t[i];return i}}).call(this,e(2))},function(t,r){var e;e=function(){return this}();try{e=e||new Function("return this")()}catch(t){"object"==typeof window&&(e=window)}t.exports=e},function(t,r,e){"use strict";r.byteLength=function(t){var r=f(t),e=r[0],n=r[1];return 3*(e+n)/4-n},r.toByteArray=function(t){var r,e,n=f(t),u=n[0],a=n[1],s=new o(function(t,r,e){return 3*(r+e)/4-e}(0,u,a)),h=0,c=a>0?u-4:u;for(e=0;e<c;e+=4)r=i[t.charCodeAt(e)]<<18|i[t.charCodeAt(e+1)]<<12|i[t.charCodeAt(e+2)]<<6|i[t.charCodeAt(e+3)],s[h++]=r>>16&255,s[h++]=r>>8&255,s[h++]=255&r;2===a&&(r=i[t.charCodeAt(e)]<<2|i[t.charCodeAt(e+1)]>>4,s[h++]=255&r);1===a&&(r=i[t.charCodeAt(e)]<<10|i[t.charCodeAt(e+1)]<<4|i[t.charCodeAt(e+2)]>>2,s[h++]=r>>8&255,s[h++]=255&r);return s},r.fromByteArray=function(t){for(var r,e=t.length,i=e%3,o=[],u=0,a=e-i;u<a;u+=16383)o.push(h(t,u,u+16383>a?a:u+16383));1===i?(r=t[e-1],o.push(n[r>>2]+n[r<<4&63]+"==")):2===i&&(r=(t[e-2]<<8)+t[e-1],o.push(n[r>>10]+n[r>>4&63]+n[r<<2&63]+"="));return o.join("")};for(var n=[],i=[],o="undefined"!=typeof Uint8Array?Uint8Array:Array,u="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",a=0,s=u.length;a<s;++a)n[a]=u[a],i[u.charCodeAt(a)]=a;function f(t){var r=t.length;if(r%4>0)throw new Error("Invalid string. Length must be a multiple of 4");var e=t.indexOf("=");return-1===e&&(e=r),[e,e===r?0:4-e%4]}function h(t,r,e){for(var i,o,u=[],a=r;a<e;a+=3)i=(t[a]<<16&16711680)+(t[a+1]<<8&65280)+(255&t[a+2]),u.push(n[(o=i)>>18&63]+n[o>>12&63]+n[o>>6&63]+n[63&o]);return u.join("")}i["-".charCodeAt(0)]=62,i["_".charCodeAt(0)]=63},function(t,r){r.read=function(t,r,e,n,i){var o,u,a=8*i-n-1,s=(1<<a)-1,f=s>>1,h=-7,c=e?i-1:0,l=e?-1:1,p=t[r+c];for(c+=l,o=p&(1<<-h)-1,p>>=-h,h+=a;h>0;o=256*o+t[r+c],c+=l,h-=8);for(u=o&(1<<-h)-1,o>>=-h,h+=n;h>0;u=256*u+t[r+c],c+=l,h-=8);if(0===o)o=1-f;else{if(o===s)return u?NaN:1/0*(p?-1:1);u+=Math.pow(2,n),o-=f}return(p?-1:1)*u*Math.pow(2,o-n)},r.write=function(t,r,e,n,i,o){var u,a,s,f=8*o-i-1,h=(1<<f)-1,c=h>>1,l=23===i?Math.pow(2,-24)-Math.pow(2,-77):0,p=n?0:o-1,y=n?1:-1,d=r<0||0===r&&1/r<0?1:0;for(r=Math.abs(r),isNaN(r)||r===1/0?(a=isNaN(r)?1:0,u=h):(u=Math.floor(Math.log(r)/Math.LN2),r*(s=Math.pow(2,-u))<1&&(u--,s*=2),(r+=u+c>=1?l/s:l*Math.pow(2,1-c))*s>=2&&(u++,s/=2),u+c>=h?(a=0,u=h):u+c>=1?(a=(r*s-1)*Math.pow(2,i),u+=c):(a=r*Math.pow(2,c-1)*Math.pow(2,i),u=0));i>=8;t[e+p]=255&a,p+=y,a/=256,i-=8);for(u=u<<i|a,f+=i;f>0;t[e+p]=255&u,p+=y,u/=256,f-=8);t[e+p-y]|=128*d}},function(t,r){var e={}.toString;t.exports=Array.isArray||function(t){return"[object Array]"==e.call(t)}}])}));
//# sourceMappingURL=web-crypto.js.map