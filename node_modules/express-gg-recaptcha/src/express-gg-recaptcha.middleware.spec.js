'use strict';

require('dotenv').config();

const axios = require('axios')

const { verifyGGRecaptchaV3 } = require('./index');

describe('::verifyRecaptchaV3 - Google Re-Captcha V3 verification middleware for Express.js', () => {

  let middleware = verifyGGRecaptchaV3(process.env.GG_RECAPTCHA_SECRET, process.env.GG_RECAPTCHA_SCORE);

  it('should throws error when a valid secret is not provided', async () => {
    try {
      const badMiddleware = verifyGGRecaptchaV3('toto');
      await badMiddleware({ body: { token: 'atoken' } }, {}, (e) => e)
    } catch(e) {
      expect(e.message).toContain('Bad parameter secret');
    }
  });

  it('should throws error when provided score is a string', async () => {
    try {
      const badMiddleware = verifyGGRecaptchaV3(process.env.GG_RECAPTCHA_SECRET, 'score');
      await badMiddleware({ body: { token: 'atoken' } }, {}, (e) => e)
    } catch(e) {
      expect(e.message).toContain('Bad parameter score');
    }
  });

  it('should throws error when provided score is lower than 0', async () => {
    try {
      const badMiddleware = verifyGGRecaptchaV3(process.env.GG_RECAPTCHA_SECRET, -1);
      await badMiddleware({ body: { token: 'atoken' } }, {}, (e) => e)
    } catch(e) {
      expect(e.message).toContain('Bad parameter score');
    }
  });

  it('should throws error when provided score is greather than 1', async () => {
    try {
      const badMiddleware = verifyGGRecaptchaV3(process.env.GG_RECAPTCHA_SECRET, 2);
      await badMiddleware({ body: { token: 'atoken' } }, {}, (e) => e)
    } catch(e) {
      expect(e.message).toContain('Bad parameter score');
    }
  });

  it('should next in Unauthorized error when request to Google API fails', async () => {
    const mockAxios = jest.spyOn(axios, 'post').mockImplementation(async (url) => {
      return Promise.resolve({
        status: 400,
        data: {
          action: 'contact'
        },
      });
    });

    const mockNext = jest.fn((error) => {
      expect(error).toBeDefined();
      expect(error.status).toEqual(401);
      expect(error.message).toContain('Re-captcha verification call failed');
    });

    await middleware({ body: { token: 'atoken' } }, {}, mockNext);

    expect(mockNext).toHaveBeenCalled(); 
    mockAxios.mockRestore();
    mockNext.mockRestore();
  });

  it('should next in Unauthorized error when Google say NO', async () => {
    const mockAxios = jest.spyOn(axios, 'post').mockImplementation(async (url) => {
      return Promise.resolve({
        status: 200,
        data: {
          action: 'contact',
          success: false,
          score: 0.1,
        },
      });
    });

    const mockNext = jest.fn((error) => {
      expect(error).toBeDefined();
      expect(error.status).toEqual(401);
      expect(error.message).toContain('Re-captcha verification call failed');
    });

    await middleware({ body: { token: 'atoken' } }, {}, mockNext);

    expect(mockNext).toHaveBeenCalled(); 
    mockAxios.mockRestore();
    mockNext.mockRestore();
  });

  it('should next in unauthorized error when Google say YES but the score is KO regarding local configuration', async () => {
    const mockAxios = jest.spyOn(axios, 'post').mockImplementation(async (url) => {
      return Promise.resolve({
        status: 200,
        data: {
          action: 'contact',
          success: true,
          score: 0.4,
        },
      });
    });
    const mockNext = jest.fn((error) => {
      expect(error).toBeDefined();
      expect(error.status).toEqual(401);
      expect(error.message).toContain('Re-captcha verification call failed');
    });

    await middleware({ body: { token: 'atoken' } }, {}, mockNext);

    expect(mockNext).toHaveBeenCalled(); 
    mockAxios.mockRestore();
    mockNext.mockRestore();
  });

  it('should next with catched error when unexpected error occurs', async () => {
    const mockAxios = jest.spyOn(axios, 'post').mockImplementation(async (url) => {
      return Promise.reject({
        status: 500,
        data: {
          action: 'contact',
          success: false,
          score: 0.4,
        },
      });
    });
    const mockNext = jest.fn((error) => {
      expect(error).toBeDefined();
      expect(error.status).toEqual(500);
    });

    await middleware({ body: { token: 'atoken' } }, {}, mockNext);

    expect(mockNext).toHaveBeenCalled(); 
    mockAxios.mockRestore();
    mockNext.mockRestore();
  });

  it('should next when Google say YES and the score is OK regarding local configuration', async () => {
    const mockAxios = jest.spyOn(axios, 'post').mockImplementation(async (url) => {
      return Promise.resolve({
        status: 200,
        data: {
          action: 'contact',
          success: true,
          score: 0.7,
        },
      });
    });
    const mockNext = jest.fn((error) => {
      expect(error).toBeUndefined();
    });

    await middleware({ body: { token: 'atoken' } }, {}, mockNext);

    expect(mockNext).toHaveBeenCalled(); 
    mockAxios.mockRestore();
    mockNext.mockRestore();
  });
});
