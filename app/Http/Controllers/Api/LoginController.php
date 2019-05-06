<?php

namespace App\Http\Controllers\Api;

use App\Components\Helpers;
use App\Http\Controllers\Controller;
use App\Http\Models\User;
use App\Http\Models\IPTable;
use App\Http\Models\mini_Card;
use App\Http\Models\UserSubscribe;
use App\Http\Models\UserSubscribeLog;
use Illuminate\Http\Request;
use App\Mail\activeUser;
use App\Mail\resetPassword;
use Response;
use Cache;
use DB;
use Auth;
use Hash;
/**
 * 登录接口
 *
 * Class LoginController
 *
 * @package App\Http\Controllers
 */
class LoginController extends Controller
{
    protected static $systemConfig;

    function __construct()
    {
        self::$systemConfig = Helpers::systemConfig();
    }

    // 登录返回订阅信息
    public function login(Request $request)
    {
        $username = trim($request->get('username'));
        $password = trim($request->get('password'));
        $remember = trim($request->get('remember'));
        $uuid = $request->get('UUID');
        $data['token'] = '';
        if (!Auth::attempt(['username' => $username, 'password' => $password], $remember)) {
            return Response::json(['status' => 'fail', 'data' => $data, 'message' => '账号或密码错误']);
        }

        $user = User::query()->where('username', $username)->where('status', '>=', 0)->first();
        if (!Auth::user()->is_admin && Auth::user()->status < 0) {
            return Response::json(['status' => 'fail', 'data' => $data, 'message' => '账号不存在或已被禁用']);
        }

        DB::beginTransaction();
        try {
            // 如果未生成过订阅链接则生成一个
            $subscribe = UserSubscribe::query()->where('user_id', $user->id)->first();
            if (!$subscribe) {
                $code = $this->makeSubscribeCode();

                $subscribe = new UserSubscribe();
                $subscribe->user_id = $user->id;
                $subscribe->code = $code;
                $subscribe->times = 0;
                $subscribe->save();
            } else {
                $code = $subscribe->code;
            }

            // 更新订阅链接访问次数
            $subscribe->increment('times', 1);

            // 记录每次请求
            $this->log($subscribe->id, getClientIp(), 'API访问');
            
            $token = str_random(64);
            User::query()->where('username', $username)->update(['remember_token' => $token]);

            // 处理用户信息
            // unset($user->password, $user->reg_ip, $user->remark, $user->usage, $user->remember_token, $user->created_at, $user->updated_at);
            // $data['user'] = $user;
            $data['token'] = $token;
            $data['level'] = $user->level;
            // 订阅链接
            // $data['link'] = self::$systemConfig['subscribe_domain'] ? self::$systemConfig['subscribe_domain'] . '/s/' . $code : self::$systemConfig['website_url'] . '/s/' . $code;

            DB::commit();

            return Response::json(['status' => 'success', 'data' => $data, 'message' => '登录成功']);
        } catch (\Exception $e) {
            DB::rollBack();

            return Response::json(['status' => 'fail', 'data' => $data, 'message' => '登录失败']);
        }
    }

    public function register(Request $request)
    {
        $cacheKey = 'register_times_' . md5(getClientIp()); // 注册限制缓存key

        if ($request->method() == 'POST') {
            $username = trim($request->get('username'));
            $password = trim($request->get('password'));
            $repassword = trim($request->get('repassword'));
            $captcha = trim($request->get('captcha'));
            $code = trim($request->get('code'));
            $verify_code = trim($request->get('verify_code'));
            $register_token = $request->get('register_token');
            $uuid = $request->get('UUID');
            $aff = intval($request->get('aff', 0));

            // 是否开启注册
            if (!self::$systemConfig['is_register']) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '系统维护，暂停注册']);
            }

            if (empty($username)) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入用户名']);
            } elseif (empty($password)) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入密码']);
            } elseif (empty($repassword)) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '请重新输入密码']);
            } elseif (md5($password) != md5($repassword)) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '两次输入密码不一致，请重新输入']);
            }

            if (preg_match('/[\x{4e00}-\x{9fa5}]/u', $username)) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '用户名禁止包含中文']);
            }
            if (strlen($username) > 16) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '用户名最大长度为 16, 请重新输入']);
            } 
            if (strlen($password) > 16 || strlen($password) < 6) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '密码的长度为 6 ~ 16, 请重新输入']);
            }

            // 如果需要邀请注册
            if (self::$systemConfig['is_invite_register']) {
                // 必须使用邀请码
                if (self::$systemConfig['is_invite_register'] == 2 && empty($code)) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入邀请码']);
                }

                // 校验邀请码合法性
                if (!empty($code)) {
                    $codeEnable = Invite::query()->where('code', $code)->where('status', 0)->first();
                    if (empty($codeEnable)) {
                        return Response::json(['status' => 'fail', 'data' => [], 'message' => '邀请码不可用，请更换邀请码后重试']);
                    }
                }
            }


            // 24小时内同IP注册限制
            if (self::$systemConfig['register_ip_limit']) {
                if (Cache::has($cacheKey)) {
                    $registerTimes = Cache::get($cacheKey);
                    if ($registerTimes >= self::$systemConfig['register_ip_limit']) {
                        return Response::json(['status' => 'fail', 'data' => [], 'message' => '系统已开启防刷机制，请勿频繁注册']);
                    }
                }
            }

            // 校验用户名是否已存在
            $exists = User::query()->where('username', $username)->exists();
            if ($exists) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '用户名已存在，请更换用户名']);
            }

            // 获取可用端口
            $port = self::$systemConfig['is_rand_port'] ? Helpers::getRandPort() : Helpers::getOnlyPort();
            if ($port > self::$systemConfig['max_port']) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '用户已满，请联系管理员']);
            }

            // 获取aff
            $affArr = $this->getAff($code, $aff);
            $referral_uid = $affArr['referral_uid'];

            $transfer_enable = $referral_uid ? (self::$systemConfig['default_traffic'] + self::$systemConfig['referral_traffic']) * 1048576 : self::$systemConfig['default_traffic'] * 1048576;

            // 创建新用户
            $user = new User();
            $user->username = $username;
            $user->password = Hash::make($password);
            $user->port = $port;
            $user->passwd = makeRandStr();
            $user->vmess_id = createGuid();
            $user->transfer_enable = $transfer_enable;
            $user->method = Helpers::getDefaultMethod();
            $user->protocol = Helpers::getDefaultProtocol();
            $user->obfs = Helpers::getDefaultObfs();
            $user->enable_time = date('Y-m-d H:i:s');
            $user->expire_time = date('Y-m-d H:i:s', strtotime("+" . self::$systemConfig['default_days'] . " days"));
            $user->reg_ip = getClientIp();
            $user->referral_uid = $referral_uid;
            $user->save();

            // 注册失败，抛出异常
            if (!$user->id) {
                Session::flash('errorMsg', '注册失败，请联系管理员');

                return Redirect::back()->withInput();
            }

            // 注册次数+1
            if (Cache::has($cacheKey)) {
                Cache::increment($cacheKey);
            } else {
                Cache::put($cacheKey, 1, 1440); // 24小时
            }

            // 初始化默认标签
            if (strlen(self::$systemConfig['initial_labels_for_user'])) {
                $labels = explode(',', self::$systemConfig['initial_labels_for_user']);
                foreach ($labels as $label) {
                    $userLabel = new UserLabel();
                    $userLabel->user_id = $user->id;
                    $userLabel->label_id = $label;
                    $userLabel->save();
                }
            }

            // 更新邀请码
            if (self::$systemConfig['is_invite_register'] && $affArr['code_id']) {
                Invite::query()->where('id', $affArr['code_id'])->update(['fuid' => $user->id, 'status' => 1]);
            }

            // 清除邀请人Cookie
            \Cookie::unqueue('register_aff');

            if (self::$systemConfig['is_verify_register']) {
                if ($referral_uid) {
                    $transfer_enable = self::$systemConfig['referral_traffic'] * 1048576;

                    User::query()->where('id', $referral_uid)->increment('transfer_enable', $transfer_enable);
                    User::query()->where('id', $referral_uid)->update(['status' => 1, 'enable' => 1]);
                }

                User::query()->where('id', $user->id)->update(['status' => 1, 'enable' => 1]);

                return Response::json(['status' => 'success', 'data' => [], 'message' => '注册成功']);
            } else {
                // 发送激活邮件
                if (self::$systemConfig['is_active_register']) {
                    // 生成激活账号的地址
                    $token = md5(self::$systemConfig['website_name'] . $username . microtime());
                    $activeUserUrl = self::$systemConfig['website_url'] . '/active/' . $token;
                    $this->addVerify($user->id, $token);

                    try {
                        Mail::to($username)->send(new activeUser($activeUserUrl));
                        Helpers::addEmailLog($username, '注册激活', '请求地址：' . $activeUserUrl);
                    } catch (\Exception $e) {
                        Helpers::addEmailLog($username, '注册激活', '请求地址：' . $activeUserUrl, 0, $e->getMessage());
                    }
                    return Response::json(['status' => 'success', 'data' => [], 'message' => '注册成功：激活邮件已发送，如未收到，请查看垃圾邮箱']);
                } else {
                    // 如果不需要激活，则直接给推荐人加流量
                    if ($referral_uid) {
                        $transfer_enable = self::$systemConfig['referral_traffic'] * 1048576;

                        User::query()->where('id', $referral_uid)->increment('transfer_enable', $transfer_enable);
                        User::query()->where('id', $referral_uid)->update(['status' => 1, 'enable' => 1]);
                    }

                    User::query()->where('id', $user->id)->update(['status' => 1, 'enable' => 1]);

                    return Response::json(['status' => 'success', 'data' => [], 'message' => '注册成功']);
                }
            }
            return Response::json(['status' => 'success', 'data' => [], 'message' => '注册成功']);
        } else {
            Session::put('register_token', makeRandStr(16));

            return Response::json(['status' => 'fail', 'data' => [], 'message' => 'register']);
        }
    }

    public function updateProxy(Request $request)
    {
        if ($request->method() == 'GET') {
            $token = trim($request->get('token'));
            
            if (!$token) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '没有 token']);
            }

            $user = User::query()->where('remember_token', $token )->where('status', '>=', 0)->first();
            if (!$user) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => 'token 过期']);
            }

            $iptable = IPTable::query()->limit(40)->get();


            $data["ip"] = $iptable;
            return Response::json(['status' => 'success', 'data' => $data, 'message' => 'token ok']);
        } else {
            return Response::json(['status' => 'fail', 'data' => [], 'message' => 'token 效验失败']);
        }
    }
    
    public function updateVersion(Request $request)
    {
        $data['version'] = '0.0.1';
        return Response::json(['status' => 'success', 'data' => $data, 'message' => 'ok']);
    }
    
    public function UpdateCard(Request $request) 
    {
        if ($request->method() == 'GET') {
            $token = trim($request->get('token'));
            
            if (!$token) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '没有 token']);
            }

            $user = User::query()->where('remember_token', $token )->where('status', '>=', 0)->first();
            if (!$user) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => 'token 过期']);
            }

            $Card = mini_Card::query()->limit(1)->get();

            $data['version'] = '0.0.1';
            $data["card"] = $Card;
            return Response::json(['status' => 'success', 'data' => $data, 'message' => 'token ok']);
        } else {
            return Response::json(['status' => 'fail', 'data' => [], 'message' => 'token 效验失败']);
        }
    }
    // 写入订阅访问日志
    private function log($subscribeId, $ip, $headers)
    {
        $log = new UserSubscribeLog();
        $log->sid = $subscribeId;
        $log->request_ip = $ip;
        $log->request_time = date('Y-m-d H:i:s');
        $log->request_header = $headers;
        $log->save();
    }
        /**
     * 获取AFF
     *
     * @param string $code 邀请码
     * @param string $aff  URL中的aff参数
     *
     * @return array
     */
    private function getAff($code = '', $aff = '')
    {
        // 邀请人ID
        $referral_uid = 0;

        // 邀请码ID
        $code_id = 0;

        // 有邀请码先用邀请码，用谁的邀请码就给谁返利
        if ($code) {
            $inviteCode = Invite::query()->where('code', $code)->where('status', 0)->first();
            if ($inviteCode) {
                $referral_uid = $inviteCode->uid;
                $code_id = $inviteCode->id;
            }
        }

        // 没有用邀请码或者邀请码是管理员生成的，则检查cookie或者url链接
        if (!$referral_uid) {
            // 检查一下cookie里有没有aff
            $cookieAff = \Request::hasCookie('register_aff') ? \Request::cookie('register_aff') : 0;
            if ($cookieAff) {
                $affUser = User::query()->where('id', $cookieAff)->exists();
                $referral_uid = $affUser ? $cookieAff : 0;
            } elseif ($aff) { // 如果cookie里没有aff，就再检查一下请求的url里有没有aff，因为有些人的浏览器会禁用了cookie，比如chrome开了隐私模式
                $affUser = User::query()->where('id', $aff)->exists();
                $referral_uid = $affUser ? $aff : 0;
            }
        }

        return [
            'referral_uid' => $referral_uid,
            'code_id'      => $code_id
        ];
    }
}