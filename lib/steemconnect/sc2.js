const fetch = require('isomorphic-fetch');

class SDKError extends Error {
  constructor(message, obj) {
    super(message);
    this.name = 'SDKError';
    this.error = obj.error;
    this.error_description = obj.error_description;
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, this.constructor);
    } else {
      this.stack = (new Error(message)).stack;
    }
  }
}

const sc2 = {
  baseURL: 'https://steemconnect.com',
  app: '',
  callbackURL: '',
  scope: [],
};

sc2.init = (params) => {
  if (params.baseURL) sc2.setBaseURL(params.baseURL);
  if (params.app) sc2.setApp(params.app);
  if (params.callbackURL) sc2.setCallbackURL(params.callbackURL);
  if (params.accessToken) sc2.setAccessToken(params.accessToken);
  if (params.scope) sc2.setScope(params.scope);
};

sc2.setBaseURL = (baseURL) => { sc2.baseURL = baseURL; };
sc2.setApp = (app) => { sc2.app = app; };
sc2.setCallbackURL = (callbackURL) => { sc2.callbackURL = callbackURL; };
sc2.setAccessToken = (accessToken) => { sc2.accessToken = accessToken; };
sc2.removeAccessToken = () => { sc2.accessToken = undefined; };
sc2.setScope = (scope) => { sc2.scope = scope; };

sc2.getLoginURL = (state) => {
  let loginURL = `${sc2.baseURL}/oauth2/authorize?client_id=${sc2.app}&redirect_uri=${encodeURIComponent(sc2.callbackURL)}`;
  loginURL += sc2.scope ? `&scope=${sc2.scope.join(',')}` : '';
  loginURL += state ? `&state=${encodeURIComponent(state)}` : '';
  return loginURL;
};
sc2.AUTHURL = () => `https://steemconnect.com/oauth2/authorize?client_id=${sc2.app}&redirect_uri=${encodeURIComponent(sc2.callbackURL)}&response_type=code&scope=comment,vote,comment_options,offline`;
sc2.send = (route, method, body, cb) => {
  const url = `${sc2.baseURL}/api/${route}`;
  const retP = fetch(url, {
    method,
    headers: {
      Accept: 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      Authorization: sc2.accessToken,
    },
    body: JSON.stringify(body),
  }).then((res) => {
    const result = res.json();
    // If the status is something other than 200 we need
    // to reject the result since the request is not considered as a fail
    if (res.status !== 200) {
      return Promise.resolve(result).then(result2 => Promise.reject(new SDKError('sc2-sdk error', result2)));
    } else if (result.error) {
      return Promise.reject(new SDKError('sc2-sdk error', result));
    }
    return Promise.resolve(result);
  });

  if (!cb) return retP;

  return retP.then((ret) => {
    if (ret.error) {
      cb(new SDKError('sc2-sdk error', ret), null);
    } else {
      cb(null, ret);
    }
  }, err => cb(new SDKError('sc2-sdk error', err), null));
};

sc2.broadcast = (operations, cb) => sc2.send('broadcast', 'POST', { operations }, cb);
sc2.me = cb => sc2.send('me', 'POST', {}, cb);

sc2.vote = (voter, author, permlink, weight, cb) => {
  const params = {
    voter,
    author,
    permlink,
    weight,
  };
  return sc2.broadcast([['vote', params]], cb);
};

sc2.comment = (parentAuthor, parentPermlink, author, permlink, title, body, jsonMetadata, cb) => {
  const params = {
    parent_author: parentAuthor,
    parent_permlink: parentPermlink,
    author,
    permlink,
    title,
    body,
    json_metadata: JSON.stringify(jsonMetadata),
  };
  return sc2.broadcast([['comment', params]], cb);
};

sc2.reblog = (account, author, permlink, cb) => {
  const params = {
    required_auths: [],
    required_posting_auths: [account],
    id: 'follow',
    json: JSON.stringify([
      'reblog', {
        account,
        author,
        permlink,
      }]),
  };
  return sc2.broadcast([['custom_json', params]], cb);
};

sc2.follow = (follower, following, cb) => {
  const params = {
    required_auths: [],
    required_posting_auths: [follower],
    id: 'follow',
    json: JSON.stringify(['follow', { follower, following, what: ['blog'] }]),
  };
  return sc2.broadcast([['custom_json', params]], cb);
};

sc2.unfollow = (unfollower, unfollowing, cb) => {
  const params = {
    required_auths: [],
    required_posting_auths: [unfollower],
    id: 'follow',
    json: JSON.stringify(['follow', { follower: unfollower, following: unfollowing, what: [] }]),
  };
  return sc2.broadcast([['custom_json', params]], cb);
};

sc2.ignore = (follower, following, cb) => {
  const params = {
    required_auths: [],
    required_posting_auths: [follower],
    id: 'follow',
    json: JSON.stringify(['follow', { follower, following, what: ['ignore'] }]),
  };
  return sc2.broadcast([['custom_json', params]], cb);
};

sc2.claimRewardBalance = (account, rewardSteem, rewardSbd, rewardVests, cb) => {
  const params = {
    account,
    reward_steem: rewardSteem,
    reward_sbd: rewardSbd,
    reward_vests: rewardVests,
  };
  return sc2.broadcast([['claim_reward_balance', params]], cb);
};

sc2.revokeToken = cb => sc2.send('oauth2/token/revoke', 'POST', { token: sc2.accessToken }, cb).then(() => sc2.removeAccessToken());

sc2.updateUserMetadata = (metadata = {}, cb) => sc2.send('me', 'PUT', { user_metadata: metadata }, cb);

sc2.sign = (name, params, redirectUri) => {
  if (typeof name !== 'string' || typeof params !== 'object') {
    return new SDKError('sc2-sdk error', {
      error: 'invalid_request',
      error_description: 'Request has an invalid format',
    });
  }
  let url = `${sc2.baseURL}/sign/${name}?`;
  url += Object.keys(params).map(key =>
    `${key}=${encodeURIComponent(params[key])}`).join('&');
  url += redirectUri ? `&redirect_uri=${encodeURIComponent(redirectUri)}` : '';
  return url;
};

module.exports = sc2;
