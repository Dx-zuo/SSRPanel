<?php

namespace App\Http\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * 标签
 * Class Label
 *
 * @package App\Http\Models
 * @mixin \Eloquent
 */
class IPTable extends Model
{
    protected $table = 'IPTable';
    protected $primaryKey = 'id';
    public $timestamps = false;

}