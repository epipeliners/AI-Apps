const axios = require('axios');

/**
 * @description Generates a middleware action for Google re-captcha
 * 
 * @param {object} logger Local logger
 * @param {string} req.body.token Google recaptcha token to validate
 * 
 * @throws {Error} 
 * @throws {Error} 
 * 
 * @returns {function} Google recaptcha V3 middleware
 * 
 * @see https://developers.google.com/search/blog/2018/10/introducing-recaptcha-v3-new-way-to
 * @see https://developers.google.com/recaptcha/docs/v3
 */
exports.verifyGGRecaptchaV3 = (secret, score = 0.7, logger = null) => async (req, res, next) => {

  if (!logger || (!logger['silly'] || !logger['debug'] || !logger['error'])) {
    logger = {
      silly: (msg) => { process.stdout.write(msg); },
      debug: (msg) => { process.stdout.write(msg); },
      error: (msg) => { process.stderr.write(msg); },
    };
  }

  logger.silly('Validation of parameters before token verification...');

  if (/^[0-9a-zA-Z]{40}$/g.test(secret) === false) {
    throw new Error(`Bad parameter secret: secret is mandatory as pattern /^[0-9a-zA-Z]{40}$/g, ${secret} given doesn't`);
  }

  if (score && isNaN(parseFloat(score, 10)) || (score < 0 || score > 1)) {
    console.log('hereiscond')
    throw new Error(`Bad parameter score: score should be a float between 0 and 1, ${score} given`);
  }

  score = Number(parseFloat(score, 10).toFixed(1));

  try {
    logger.silly('Calling google recaptcha API...');
    const response = await axios.default.post(`https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${req.body.token}`);

    if (response.status !== 200 || (response.data && !response.data.success)) {
      logger.error('Re-captcha verification call failed');
      return next({ status: 401, statusCode: 401, message: 'Re-captcha verification call failed' });
    }

    if (response.status === 200 && response.data.success && (parseFloat(response.data.score) < parseFloat(score))) {
      logger.error(`Re-captcha verification failed: ${response.data?.action} - score ${response.data?.score} (${score} required)`);
      return next({ status: 401, statusCode: 401, message: 'Re-captcha verification call failed' });
    }

    logger.debug(`Re-captcha verification succesful: ${response.data?.action} - score ${response.data?.score} (${score} required)`);
    
    // Sanitize payload by removing Google recaptcha token
    delete req.body.token;

    next();
  } catch (e) {
    next(e);
  }
};
