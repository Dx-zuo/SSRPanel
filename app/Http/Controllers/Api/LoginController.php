<?php

namespace App\Http\Controllers\Api;

use App\Components\Helpers;
use App\Components\CaptchaVerify;
use App\Http\Controllers\Controller;
use App\Http\Models\User;
use App\Http\Models\UserLabel;
use App\Http\Models\UserSubscribe;
use App\Http\Models\UserSubscribeLog;
use App\Http\Models\Invite;
use Illuminate\Http\Request;
use Response;
use Cache;
use Hash;
use DB;
use Auth;
use Session;
use Validator;
use Redirect;
use Captcha;
use Log;

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
        $UUID = trim($request->get('UUID'));
        $cacheKey = 'request_times_' . md5(getClientIp());

        if (!$username || !$password) {
            Cache::increment($cacheKey);

            return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入用户名和密码']);
        }
        if (!$UUID) {
            return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入 UUID']);

        }
        // 连续请求失败15次，则封IP一小时
        if (Cache::has($cacheKey)) {
            if (Cache::get($cacheKey) >= 15) {
                return Response::json(['status' => 'fail', 'data' => [], 'message' => '请求失败超限，禁止访问1小时']);
            }
        } else {
            Cache::put($cacheKey, 1, 60);
        }

        $user = User::query()->where('username', $username)->where('status', '>=', 0)->first();
        if (!$user) {
            Cache::increment($cacheKey);

            return Response::json(['status' => 'fail', 'data' => [], 'message' => '账号不存在或已被禁用']);
        } elseif (!Hash::check($password, $user->password)) {
            return Response::json(['status' => 'fail', 'data' => [], 'message' => '用户名或密码错误']);
        }

        DB::beginTransaction();
        try {
            // 如果未生成过订阅链接则生成一个
            $subscribe = UserSubscribe::query()->where('user_id', $user->id)->first();

            // 更新订阅链接访问次数
            $subscribe->increment('times', 1);

            // 记录每次请求
            $this->log($subscribe->id, getClientIp(), 'API访问');

            // 订阅链接
            $url = self::$systemConfig['subscribe_domain'] ? self::$systemConfig['subscribe_domain'] : self::$systemConfig['website_url'];

            // 节点列表
            $userLabelIds = UserLabel::query()->where('user_id', $user->id)->pluck('label_id');
            if (empty($userLabelIds)) {
                return Response::json(['status' => 'fail', 'message' => '', 'data' => []]);
            }

            $nodeList = DB::table('ss_node')
                ->selectRaw('ss_node.*')
                ->leftJoin('ss_node_label', 'ss_node.id', '=', 'ss_node_label.node_id')
                ->whereIn('ss_node_label.label_id', $userLabelIds)
                ->where('ss_node.status', 1)
                ->groupBy('ss_node.id')
                ->orderBy('ss_node.sort', 'desc')
                ->orderBy('ss_node.id', 'asc')
                ->get();

            $c_nodes = collect();
            foreach ($nodeList as $node) {
                $temp_node = [
                    'name'          => $node->name,
                    'server'        => $node->server,
                    'server_port'   => $user->port,
                    'method'        => $user->method,
                    'obfs'          => $user->obfs,
                    'flags'         => $url . '/assets/images/country/' . $node->country_code . '.png',
                    'obfsparam'     => '',
                    'password'      => $user->passwd,
                    'group'         => '',
                    'protocol'      => $user->protocol,
                    'protoparam'    => '',
                    'protocolparam' => ''
                ];
                $c_nodes = $c_nodes->push($temp_node);
            }

            $user->remember_token = substr(Hash::make(date('Y-m-d H:i:s')),15);
            $user->vmess_id = $UUID;
            $user->save();
            DB::commit();
            // $user->update();
            $data = [
                'status'       => 1,
                'class'        => 0,
                'level'        => 2,
                'expire_in'    => $user->expire_time,
                // 'text'         => '',
                // 'buy_link'     => '',
                'money'        => '0.00',
                'usedTraffic'  => flowAutoShow($user->u + $user->d),
                'Traffic'      => flowAutoShow($user->transfer_enable),
                'all'          => 1,
                'residue'      => '',
                'expire_time'  => $user->expire_time,
                'token'        => $user->remember_token,
                // 'nodes'        => $c_nodes,
                // 'link'         => $url . '/s/' . $subscribe->code
            ];


            return Response::json(['status' => 'success', 'data' => $data, 'message' => '登录成功']);
        } catch (\Exception $e) {
            DB::rollBack();

            return Response::json(['status' => 'success', 'data' => [], 'message' => '登录失败']);
        }
    }
       // 注册
       public function register(Request $request)
       {
           $cacheKey = 'register_times_' . md5(getClientIp()); // 注册限制缓存key
           if ($request->isMethod('POST')) {
            //    $this->validate($request, [
            //        'username'   => 'required|min:6|unique:user',
            //        'password'   => 'required|min:6',
            //        'repassword' => 'required|same:password',
            //    ], [
            //        'username.required'   => '请输入用户名',
            //        'username.min'      => '用户名最少要3位数',
            //        'username.unique'     => '用户已存在，如果忘记密码请找回密码',
            //        'password.required'   => '请输入密码',
            //        'password.min'        => '密码最少要6位数',
            //        'repassword.required' => '请再次输入密码',
            //        'repassword.same'     => '两次输入密码不一致'
            //    ]);
                if (!$request->username) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入用户名']);
                }
                if (!$request->password) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入 密码']);
                }
                if (!$request->UUID) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入 UUID']);
                }
                $user = User::query()->where('username', $request->username)->where('status', '>=', 0)->first();
                if ($user) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '用户名重复 请重新输入']);
                }

                $user = User::query()->where('referral_uid', $request->UUID)->where('status', '>=', 0)->first();
                if ($user) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => ' 设备重复注册 请使用用户名登录']);
                }
               // 防止重复提交
               if ($request->register_token != Session::get('register_token')) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '请勿重复请求，刷新一下页面再试试']);
               } else {
                   Session::forget('register_token');
               }

               // 是否开启注册
               if (!self::$systemConfig['is_register']) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '请系统维护，暂停注册']);
               }
   
               // 如果需要邀请注册
               if (self::$systemConfig['is_invite_register']) {
                   // 必须使用邀请码
                   if (self::$systemConfig['is_invite_register'] == 2 && !$request->code) {
                        return Response::json(['status' => 'fail', 'data' => [], 'message' => '请输入邀请码']);
                   }
   
                   // 校验邀请码合法性
                   if ($request->code) {
                       $codeEnable = Invite::query()->where('code', $request->code)->where('status', 0)->first();
                       if (!$codeEnable) {
                            return Response::json(['status' => 'fail', 'data' => [], 'message' => '邀请码不可用，请重试']);
                       }
                   }
               }

               // 如果开启注册发送验证码
               if (self::$systemConfig['is_verify_register']) {
                   if (!$request->verify_code) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '邀请码不可用，请重试']);
                } else {
                       $verifyCode = VerifyCode::query()->where('username', $request->username)->where('code', $request->verify_code)->where('status', 0)->first();
                       if (!$verifyCode) {
                        return Response::json(['status' => 'fail', 'data' => [], 'message' => '邀请码不可用，请重试']);
                    }
   
                       $verifyCode->status = 1;
                       $verifyCode->save();
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

               // 获取可用端口
               $port = self::$systemConfig['is_rand_port'] ? Helpers::getRandPort() : Helpers::getOnlyPort();
               if ($port > self::$systemConfig['max_port']) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '系统不再接受新用户，请联系管理员']);
               }

               // 获取aff
            //    $affArr = $this->getAff($request->code, intval($request->aff));
            if ($request->UUID) {
                $referral_uid = $request->UUID;
            } else {
                $referral_uid = '';
            }

               $transfer_enable = $referral_uid ? (self::$systemConfig['default_traffic'] + self::$systemConfig['referral_traffic']) * 1048576 : self::$systemConfig['default_traffic'] * 1048576;

               // 创建新用户
               $user = new User();
               $user->username = $request->username;
               $user->password = Hash::make($request->password);
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
               $user->remember_token = substr(Hash::make(date('Y-m-d H:i:s')),15);
               try{ 
                $user->save();
                }catch(\Illuminate\Database\QueryException $e){ 
                    return Response::json(['status' => 'fail', 'data' => $e, 'message' => '账号重复请重新输入']);
                }


               // 注册失败，抛出异常
               if (!$user->id) {
                    return Response::json(['status' => 'fail', 'data' => [], 'message' => '注册失败，请联系管理员']);
               }
               return Response::json(['status' => 'success', 'data' => ['token' => $user->remember_token], 'message' => '注册成功']);

               // 生成订阅码
               $subscribe = new UserSubscribe();
               $subscribe->user_id = $user->id;
               $subscribe->code = Helpers::makeSubscribeCode();
               $subscribe->times = 0;
               $subscribe->save();
   
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
   
                   Session::flash('regSuccessMsg', '注册成功');
               } else {
                   // 发送激活邮件
                   if (self::$systemConfig['is_active_register']) {
                       // 生成激活账号的地址
                       $token = md5(self::$systemConfig['website_name'] . $request->username . microtime());
                       $activeUserUrl = self::$systemConfig['website_url'] . '/active/' . $token;
                       $this->addVerify($user->id, $token);
   
                       $logId = Helpers::addEmailLog($request->username, '注册激活', '请求地址：' . $activeUserUrl);
                       Mail::to($request->username)->send(new activeUser($logId, $activeUserUrl));
   
                       Session::flash('regSuccessMsg', '注册成功：激活邮件已发送，如未收到，请查看垃圾邮箱');
                   } else {
                       // 如果不需要激活，则直接给推荐人加流量
                       if ($referral_uid) {
                           $transfer_enable = self::$systemConfig['referral_traffic'] * 1048576;
   
                           User::query()->where('id', $referral_uid)->increment('transfer_enable', $transfer_enable);
                           User::query()->where('id', $referral_uid)->update(['status' => 1, 'enable' => 1]);
                       }
   
                       User::query()->where('id', $user->id)->update(['status' => 1, 'enable' => 1]);
   
                       Session::flash('regSuccessMsg', '注册成功');
                   }
               }
   
               return Redirect::to('login')->withInput();
           } else {
               Session::put('register_token', makeRandStr(16));
   
               return Response::view('auth.register');
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
}