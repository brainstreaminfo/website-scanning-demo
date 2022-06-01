<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * Class ScanResponse
 * @package App\Models
 */
class ScanResponse extends Model
{
    use HasFactory;

    /**
     * @var string
     */
    protected $table = 'scan_res';

    /**
     * @var array
     */
    protected $fillable = [
        'scan_full_res_id',
        'is_siteup',
        'ttfb',
        'loadtime',
        'is_tls10',
        'is_tls11',
        'is_tls12',
        'is_tls13',
        'mixedcontent',
        'brokenlink',
        'screenshot',
        'speed_index',
        'index_errors',
        'is_safe_browsing',
        'is_mobile_friendly',
        'x_frame_options',
        'x_xss_protection',
        'is_HSTS',
        'secure_cookie',
        'is_blacklist',
        'wp_version',
        'vulnerabilities_count',
        'vulnerability_json',
    ];
}
