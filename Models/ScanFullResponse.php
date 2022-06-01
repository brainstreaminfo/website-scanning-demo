<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * Class ScanFullResponse
 * @package App\Models
 */
class ScanFullResponse extends Model
{
    use HasFactory;

    /**
     * @var string
     */
    protected $table = 'scan_full_res';

    /**
     * @var array
     */
    protected $fillable = [
        'website_url',
        'scan_unq_id',
        'scan_response',
    ];
}
