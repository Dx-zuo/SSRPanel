<?php

namespace App\Http\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * 等级
 * Class Level
 *
 * @package App\Http\Models
 * @mixin \Eloquent
 */
class mini_Card extends Model
{
    protected $table = 'mini_Card';
    protected $primaryKey = 'id';
    public $timestamps = false;
}