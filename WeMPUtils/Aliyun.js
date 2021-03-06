class State {
  state = {};
  getState() { return this.state }
  setState(r) { Object.assign(this.state, r) }
}
class OSS extends State {
  B64HMACSHA1;
  B64MD5;
  Base64;
  DOMparser;
  constructor({
    XML = './dom-parser.js',
    B64MD5 = './md5.js',
    B64HMACSHA1 = './hmac_sha1.js',
    accessKeyId,
    accessKeySecret,
    bucketName,
    conditions = [{}],
    endPoint = '',
    expiresIn = 900,
    securityToken = 0,
    tokenExpires = Date.parse(new Date()) / 1000 + 3600,
  } = {}) {
    super();
    if (accessKeyId === undefined || accessKeySecret === undefined || typeof Base64 !== 'function')
      throw new Error('Param missing! \nPlease use me like this: \n\nnew OSS({\n\taccessKeyId: "",\n\taccessKeySecret: ""\n});\n\n');
    Object.assign(this.state, {
      bucketName,
      conditions,
      endPoint,
      expiresIn,
      id: accessKeyId,
      secret: accessKeySecret,
      token: securityToken,
      tokenExpires,
    });
    this.Base64 = new Base64();
    this.DOMparser = XML ? new (require(XML)).DOMParser() : undefined;
    this.B64MD5 = B64MD5 ? require(B64MD5).base64 : undefined;
    this.B64HMACSHA1 = B64HMACSHA1 ? require(B64HMACSHA1) : undefined;
  }
  getSignature({
    bucketName = this.state.bucketName,
    data = '',
    endPoint = this.state.endPoint,
    expiresIn = this.state.expiresIn,
    extraHeader = { 'content-type': 'application/xml' },
    method = 'GET',
    resourse,
  } = {}) {
    if (resourse === undefined)
      throw new Error('\nParam missing!\n\n');
    let expires = parseInt(Date.parse(new Date()) / 1000 + expiresIn);
    data = this.B64MD5(data);
    this.state.token ? extraHeader['x-oss-security-token'] = this.state.token : 0;
    let s = [method, data, extraHeader['content-type'], expires];
    Object.keys(extraHeader).map(k => k.search(/x-oss-/i) === 0 ? s.push(k + ':' + extraHeader[k]) : 0);
    s.push(resourse);
    s = s.join('\n');
    s = this.B64HMACSHA1(this.state.secret, s);
    resourse = resourse.replace(bucketName ? '/' + bucketName + '/' : /\/[^\/]{1,}\//, '');
    return {
      expires,
      header: Object.assign(extraHeader, { 'content-md5': data }),
      signature: s,
      url: endPoint
        + resourse
        + (resourse.search(/\?/) === -1 ? '?' : '&')
        + 'Expires=' + expires
        + '&Signature=' + encodeURIComponent(s)
        + '&OSSAccessKeyId=' + this.state.id,
    };
  }
  getObject({
    bucketName = this.state.bucketName,
    download,
    endPoint = this.state.endPoint,
    extraHeader,
    key,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || key === undefined || bucketName === undefined)
      throw new Error('\nParam missing!\n\n');
    let resourse = '/' + bucketName + '/' + key;
    let { header, url } = this.getSignature({ bucketName, endPoint, extraHeader, resourse });
    let s = r => { if (r.statusCode < 300) { success(r) } else { fail(r) } };
    return download
      ? wx.downloadFile({ url, header, success: s, fail, complete })
      : wx.request({ url, header, success: s, fail, complete });
  }
  putObject({
    bucketName = this.state.bucketName,
    data = '',
    endPoint = this.state.endPoint,
    extraHeader,
    key,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || key === undefined || bucketName === undefined)
      throw new Error('\nParam missing!\n\n');
    let resourse = '/' + bucketName + '/' + key, method = 'PUT';
    let { header, url } = this.getSignature({ bucketName, data, endPoint, extraHeader, method, resourse });
    let s = r => { if (r.statusCode < 300) { success(r) } else { fail(r) } };
    return wx.request({ url, method, header, data, success: s, fail, complete });
  }
  postObject({
    endPoint = this.state.endPoint,
    extraHeader = {},
    filePath,
    key = '${filename}',
    expiresIn = this.state.expiresIn,
    conditions = this.state.conditions,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || filePath === undefined)
      throw new Error('\nParam missing!\n\n');
    let e = new Date(), policy;
    conditions === this.state.conditions && this.state._policy && this.state._policyExpires > parseInt(Date.parse(e) / 1000 + 9)
      ? policy = this.state._policy
      : (() => {
        e.setTime(Date.parse(e) + expiresIn * 1000);
        policy = this.Base64.encode(JSON.stringify({ expiration: e.toISOString(), conditions }));
        [this.state._policy, this.state._policyExpires] = [policy, parseInt(Date.parse(e) / 1000)];
      })();
    this.state.token ? extraHeader['x-oss-security-token'] = this.state.token : 0;
    let s = r => { if (r.statusCode < 300) { success(r) } else { fail(r) } };
    return wx.uploadFile({
      url: endPoint,
      filePath,
      name: 'file',
      formData: Object.assign(extraHeader, {
        key,
        OSSAccessKeyId: this.state.id,
        policy,
        Signature: this.B64HMACSHA1(this.state.secret, policy),
        success_action_status: '200',
      }),
      success: s,
      fail,
      complete,
    });
  }
  listObjects({
    bucketName = this.state.bucketName,
    delimiter = '/',
    endPoint = this.state.endPoint,
    expiresIn = this.state.expiresIn,
    header,
    marker,
    maxKeys,
    prefix = null,
    url,
    urlExpires,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!url || !header || !urlExpires || urlExpires < parseInt(Date.parse(new Date()) / 1000 + 9)) {
      if (!endPoint || bucketName === undefined)
        throw new Error('\nParam missing!\n\n');
      let resourse = '/' + bucketName + '/';
      let r = this.getSignature({ bucketName, endPoint, expiresIn, resourse });
      [header, url, urlExpires] = [r.header, r.url, r.expires];
      url += [''
        , prefix ? 'prefix=' + prefix : ''
        , maxKeys ? 'max-keys=' + maxKeys : ''
        , marker ? 'marker=' + marker : ''
        , delimiter ? 'delimiter=' + delimiter : ''
      ].join('&');
    }
    let s = r => {
      if (r.statusCode < 300) {
        Object.assign(r, {
          url,
          header,
          urlExpires,
          isTruncated: this.DOMparser.parseFromString(r.data).getElementsByTagName('IsTruncated')[0].firstChild.data,
          prefix,
          dir: Array.from(this.DOMparser.parseFromString(r.data).getElementsByTagName('Prefix')).slice(1).map(k => k.firstChild.data),
          key: Array.from(this.DOMparser.parseFromString(r.data).getElementsByTagName('Key')).map(k => k.firstChild.data),
        });
        success(r);
      } else { fail(r) }
    };
    return wx.request({ url, header, success: s, fail, complete });
  }
  deleteObject({
    bucketName = this.state.bucketName,
    endPoint = this.state.endPoint,
    key,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || key === undefined || bucketName === undefined)
      throw new Error('\nParam missing!\n\n');
    let resourse = '/' + bucketName + '/' + key, method = 'DELETE';
    let { header, url } = this.getSignature({ bucketName, endPoint, method, resourse });
    let s = r => { if (r.statusCode < 300) { success(r) } else { fail(r) } };
    return wx.request({ url, method, header, success: s, fail, complete });
  }
  deleteMultipleObjects({
    bucketName = this.state.bucketName,
    endPoint = this.state.endPoint,
    key = [],
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || bucketName === undefined)
      throw new Error('\nParam missing!\n\n');
    let data = '<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>true</Quiet><Object><Key><![CDATA['
      + key.join(']]></Key></Object><Object><Key><![CDATA[')
      + ']]></Key></Object></Delete>';
    let resourse = '/' + bucketName + '/?delete', method = 'POST';
    let { header, url } = this.getSignature({ bucketName, data, endPoint, method, resourse });
    let s = r => { if (r.statusCode < 300) { success(r) } else { fail(r) } };
    return wx.request({ url, method, header, data, success: s, fail, complete });
  }
  headObject({
    bucketName = this.state.bucketName,
    endPoint = this.state.endPoint,
    extraHeader,
    key,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || key === undefined || bucketName === undefined)
      throw new Error('\nParam missing!\n\n');
    let resourse = '/' + bucketName + '/' + key, method = 'HEAD';
    let { header, url } = this.getSignature({ bucketName, endPoint, extraHeader, method, resourse });
    let s = r => { if (r.statusCode < 300) { success(r) } else { fail(r) } };
    return wx.request({ url, method, header, success: s, fail, complete });
  }
  appendObject({
    bucketName = this.state.bucketName,
    data = '',
    endPoint = this.state.endPoint,
    extraHeader,
    key,
    position = 0,
    retry = false,
    success = () => { },
    fail = () => { },
    complete = () => { },
  } = {}) {
    if (!endPoint || key === undefined || bucketName === undefined)
      throw new Error('\nParam missing!\n\n');
    let resourse = '/' + bucketName + '/' + key + '?append&position=' + position, method = 'POST';
    let { header, url } = this.getSignature({ bucketName, data, endPoint, extraHeader, method, resourse });
    let s = r => {
      if (r.statusCode < 300) { success(r) }
      else if (r.statusCode === 409 && retry) {
        this.appendObject({
          bucketName,
          data,
          endPoint,
          extraHeader,
          key,
          position: r.header['x-oss-next-append-position'],
          success,
          fail,
          complete,
        });
      }
      else { fail(r) }
    };
    return wx.request({ url, method, header, data, success: s, fail, complete });
  }
}
class Base64 {
  m = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  encode(s = '') {
    let a, d = '', i = 0, l = s.length - 3;
    for (; i < l;) {
      a = [s.charCodeAt(i++).toString(2), s.charCodeAt(i++).toString(2), s.charCodeAt(i++).toString(2)];
      a = a.map(k => '00000000'.slice(k.length) + k).join('');
      d += this.m[parseInt(a.slice(0, 6), 2)];
      d += this.m[parseInt(a.slice(6, 12), 2)];
      d += this.m[parseInt(a.slice(12, 18), 2)];
      d += this.m[parseInt(a.slice(18, 24), 2)];
    }
    a = [s.charCodeAt(i++).toString(2)
      , s.charCodeAt(i++).toString(2).replace('NaN', '')
      , s.charCodeAt(i++).toString(2).replace('NaN', '')
    ];
    a = a.map(k => '00000000'.slice(k.length) + k).join('');
    return d + [parseInt(a.slice(0, 6), 2)
      , parseInt(a.slice(6, 12), 2)
      , parseInt(a.slice(12, 18), 2)
      , parseInt(a.slice(18, 24), 2)
    ].map(k => k ? this.m[k] : '=').join('');
  }
  decode(s = '') {
    let a, d = '', i = 0, l = s.length - 4;
    for (; i < l;) {
      a = [this.m.indexOf(s[i++]).toString(2)
        , this.m.indexOf(s[i++]).toString(2)
        , this.m.indexOf(s[i++]).toString(2)
        , this.m.indexOf(s[i++]).toString(2)
      ];
      a = a.map(k => '000000'.slice(k.length) + k).join('');
      d += String.fromCharCode(parseInt(a.slice(0, 8), 2))
        + String.fromCharCode(parseInt(a.slice(8, 16), 2))
        + String.fromCharCode(parseInt(a.slice(16, 24), 2));
    }
    for (a = ''; i < s.length;) {
      l = this.m.indexOf(s[i++]).toString(2);
      a += l === '-1' ? '' : '000000'.slice(l.length) + l;
    }
    for (i = 0; i < parseInt(a.length / 8);)
      d += String.fromCharCode(parseInt(a.slice(i++ * 8, i * 8), 2));
    return d;
  }
}
export { OSS, Base64 };