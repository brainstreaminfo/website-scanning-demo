<?php

namespace App\Jobs;

use App\Helpers\MauticHelper;
use App\Models\ScanFullResponse;
use App\Models\ScanResponse;
use App\Models\Vulnerability;
use Exception;
use Mautic\MauticApi;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Bus\Queueable;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

/**
 * Class ScanTools
 * @package App\Jobs
 */
class ScanTools
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * @var string
     */
    protected $data;

    /**
     * Create a new job instance.
     *
     * @return void
     */
    public function __construct($data)
    {
        $this->data = $data;
    }

    /**
     * Execute the job.
     *
     * @return void
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function handle()
    {
        try {
            //website url which need to verify
            $scanData   = $this->data;
            $apiKey     = 'abcd1234';
            $gfApiUrl   = 'example.com';

            foreach ($scanData as $scan) {
                $data           = [];
                $requestUrl     = $scan['url'];
                //headers for APIs
                $headers = [
                    'content-type'      => 'application/json',
                    'x-rapidapi-host'   => 'example.com',
                    'x-rapidapi-key'    => $apiKey
                ];
                //example endpoints list
                $endpointsList = ['up', 'ttfb', 'loadtime', 'tlsscan', 'mixedcontent', 'brokenlink', 'screenshot', 'lighthouse'];

                foreach ($endpointsList as $singleReq) {
                    $client     = new \GuzzleHttp\Client(['headers' => $headers]);
                    $body       = json_encode(['url' => $requestUrl]);
                    $response   = $client->request('POST', $gfApiUrl . $singleReq, ['body' => $body]);

                    if ($response->getStatusCode() == Response::HTTP_OK || $response->getStatusCode() == Response::HTTP_CREATED) {
                        $responseData = json_decode($response->getBody()->getContents());

                        switch ($singleReq) {
                            case "up":
                                if ($responseData->data[0]->description == "Site is up.") {
                                    $data['siteup'] = true;
                                } else {
                                    $data['siteup'] = false;
                                }

                                break;
                            case "ttfb":
                                if (isset($responseData->data[0]->ttfb)) {
                                    $data['ttfb'] = $responseData->data[0]->ttfb . ' ms';
                                } else {
                                    $data['ttfb'] = 'N/A';
                                }

                                break;
                            case "loadtime":
                                if (isset($responseData->data[0]->total)) {
                                    $data['loadtime'] = $responseData->data[0]->total . ' ms';
                                } else {
                                    $data['loadtime'] = "N/A";
                                }

                                break;
                            case "tlsscan":
                                $tlsscan['tls10']   = ($responseData->data->protocols->tls10) ? true : false;
                                $tlsscan['tls11']   = ($responseData->data->protocols->tls11) ? true : false;
                                $tlsscan['tls12']   = ($responseData->data->protocols->tls12) ? true : false;
                                $tlsscan['tls13']   = ($responseData->data->protocols->tls13) ? true : false;
                                $data['tlsscan']    = $tlsscan;

                                break;
                            case "mixedcontent":
                                $data['mixedcontent'] = $responseData;
                                $mixedContentCount    = false;

                                if($responseData->message == 'Mixed content(s) found.'){
                                    if(isset($responseData->data->insecure)){
                                        $mixedContentCount   = count($responseData->data->insecure);
                                    }
                                }

                                break;
                            case "brokenlink":
                                $broken_cnt   = false;
                                $broken_links = [];

                                if (isset($responseData->data)) {
                                    foreach ($responseData->data as $broken) {
                                        if ($broken->status != Response::HTTP_OK) {
                                            $broken_links[]     = json_encode($broken);
                                            $broken_cnt         = $broken_cnt + 1;
                                        }
                                    }
                                }
                                $data['brokenlink']['brokenlink_count'] = $broken_cnt;
                                $data['brokenlink']['data']             = $broken_links;

                                break;
                            case "screenshot":
                                $data['screenshot'] = $responseData->data[0]->screenshot;

                                break;
                            case "lighthouse":
                                $fileLink   = $responseData->data;
                                $client     = new \GuzzleHttp\Client();
                                $res        = $client->request('GET', $fileLink);
                                $fileStr    = utf8_encode($res->getBody()->getContents());
                                $fileResult = json_decode($fileStr, true);

                                if (isset($fileResult['audits']['first-contentful-paint']['displayValue'])) {
                                    $data['first_contentful_paint'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $fileResult['audits']['first-contentful-paint']['displayValue']);
                                }

                                if (isset($fileResult['audits']['speed-index']['displayValue'])) {
                                    $data['speed_index'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $fileResult['audits']['speed-index']['displayValue']);
                                } else {
                                    $data['speed_index'] = "N/A";
                                }

                                if (isset($fileResult['audits']['largest-contentful-paint']['displayValue'])) {
                                    $data['largest_contentful_paint'] = preg_replace('/[^A-Za-z0-9 _\-\+\&]/', '', $fileResult['audits']['largest-contentful-paint']['displayValue']);
                                }

                                if (isset($fileResult['audits']['total-blocking-time']['displayValue'])) {
                                    $data['total_blocking_time'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $fileResult['audits']['total-blocking-time']['displayValue']);
                                }

                                if (isset($fileResult['audits']['interactive']['displayValue'])) {
                                    $data['interactive'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $fileResult['audits']['interactive']['displayValue']);
                                }

                                if (isset($fileResult['audits']['is-crawlable']['displayValue'])) {
                                    $data['crawl-errors'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $fileResult['audits']['is-crawlable']['score']);
                                }

                                if (isset($fileResult['audits']['robots-txt']['displayValue'])) {
                                    $data['index-errors'] = json_encode($fileResult['audits']['robots-txt']['details']);
                                } else {
                                    $data['index-errors'] = false;
                                }

                                break;
                            default:
                        }
                    }
                    sleep(1);
                }

                //google safe browsing API
                $headers        = [ 'content-type' => 'application/json' ];
                $googleApiKey   = 'abcd123!@#';
                $gglApiUrl      = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $googleApiKey;
                $client         = new \GuzzleHttp\Client(['headers' => $headers]);
                $body           = [
                    'threatInfo' => [
                        'threatTypes' => [
                            'MALWARE',
                            'SOCIAL_ENGINEERING',
                        ],
                        'threatEntryTypes' => [
                            'URL',
                        ],
                        'threatEntries' => [
                            [
                                'url' => 'http://www.urltocheck1.org/',
                            ]
                        ],
                    ],
                ];
                $body           = json_encode($body);
                $response       = $client->request('POST', $gglApiUrl, ['body' => $body]);

                if ($response->getStatusCode() == Response::HTTP_OK) {
                    $responseData = json_decode($response->getBody()->getContents(), 1);

                    if (count($responseData) > 0) {
                        //not safe browsing
                        $data['safe_browsing'] = false;
                    } else {
                        //safe browsing
                        $data['safe_browsing'] = true;
                    }
                }
                //google mobile resposive API
                $data['mobile_friendly']    = $this->checkMobileResponsive($headers, $requestUrl, $googleApiKey);
                $headers                    = get_headers($requestUrl);
                $xFrameOptions              = "N/A";
                $hsts                       = "N/A";
                $xXssProtection             = "N/A";
                $secureCookie               = "N/A";
                $secureHeaders              = [
                                                'strict_transport_security' => "N/A",
                                                'public_key_pins' => "N/A",
                                                'content_security_policy' => "N/A",
                                                'referrer_policy' => "N/A",
                                                'expect_ct' => "N/A",
                                                'feature_policy' => "N/A",
                                                'x_frame_options' => "N/A",
                                                'x_xss_protection' => "N/A",
                                                'x_content_type_options' => "N/A",
                                                'x_permitted_cross_domain_policies' => "N/A"
                                              ];

                foreach ($headers as $key => $header) {
                    if (strpos($header, 'Public-Key-Pins') !== false) {
                        $secureHeaders['public_key_pins'] = trim(str_replace('Public-Key-Pins:', '', $header));
                    }

                    if (strpos($header, 'Referrer-Policy') !== false) {
                        $secureHeaders['referrer_policy'] = trim(str_replace('Referrer-Policy:', '', $header));
                    }

                    if (strpos($header, 'Expect-CT') !== false) {
                        $secureHeaders['expect_ct'] = trim(str_replace('Expect-CT:', '', $header));
                    }

                    if (strpos($header, 'Feature-Policy') !== false) {
                        $secureHeaders['feature_policy'] = trim(str_replace('Feature-Policy:', '', $header));
                    }

                    if (strpos($header, 'X-Content-Type-Options') !== false) {
                        $secureHeaders['x_content_type_options'] = trim(str_replace('X-Content-Type-Options:', '', $header));
                    }

                    if (strpos($header, 'X-Permitted-Cross-Domain-Policies') !== false) {
                        $secureHeaders['x_permitted_cross_domain_policies'] = trim(str_replace('X-Permitted-Cross-Domain-Policies:', '', $header));
                    }

                    if (strpos($header, 'X-Frame-Options') !== false) {
                        $xFrameOptions                      = trim(str_replace('X-Frame-Options:', '', $header));
                        $secureHeaders['x_frame_options']   = trim(str_replace('X-Frame-Options:', '', $header));
                    }

                    if (strpos($header, 'Strict-Transport-Security') !== false) {
                        $hsts                                           = trim(str_replace('Strict-Transport-Security:', '', $header));
                        $secureHeaders['strict_transport_security']     = trim(str_replace('Strict-Transport-Security:', '', $header));
                    }

                    if (strpos($header, 'X-XSS-Protection') !== false) {
                        $xXssProtection                     = trim(str_replace('X-XSS-Protection:', '', $header));
                        $secureHeaders['x_xss_protection']  = "available";
                    }

                    if (strpos($header, 'Content-Security-Policy') !== false) {
                        $csp = trim(str_replace('Content-Security-Policy:', '', $header));
                        $secureHeaders['content_security_policy'] = trim(str_replace('Content-Security-Policy:', '', $header));
                    }

                    if (strpos($header, 'X-Permitted-Cross-Domain-Policies') !== false) {
                        $cross_domain_policy = trim(str_replace('X-Permitted-Cross-Domain-Policies:', '', $header));
                    }

                    if (strpos($header, 'set-cookie') !== false) {
                        $secureCookie = trim(str_replace('set-cookie:', '', $header));
                    }
                }
                $data['secure_headers']     = $secureHeaders;
                $data['x_frame_options']    = $xFrameOptions;
                $data['HSTS']               = ($hsts != "N/A") ? true : false;
                $data['x-xss-protection']   = $xXssProtection;
                $data['secure_cookie']      = $secureCookie;
                //get wp version
                $meta                       = $this->checkMetaTag($requestUrl);
                $feed                       = $this->checkFeed($requestUrl);

                if ($feed['success']) {
                    $data['wp_version']     = $feed['wp_version'];
                } elseif ($meta['success']) {
                    $data['wp_version']     = $meta['wp_version'];
                } else {
                    $data['wp_version']     = 'N/A';
                }
                //get wp_vulnerability
                $vulnerability              = null;

                if ($data['wp_version'] != 'N/A') {
                    $wpMainVersion      = floatval(substr($data['wp_version'], 0, 3));
                    ($wpMainVersion <= 5.0) ? $checkWpVersion = "5.0" : $checkWpVersion = $wpMainVersion;
                    $vulnerability      = Vulnerability::select('vulnerabilities')->where('wp_version', $checkWpVersion)->first();
                }

                if ($vulnerability != null) {
                    $data['wp_vulnerability'] = $vulnerability->vulnerabilities;
                    $data['wp_vulnerability'] = trim($data['wp_vulnerability'],'"');
                } else {
                    $data['wp_vulnerability'] = 'N/A';
                }

                //insert record in scan_full_res table
                $uniqueId                           = Str::random(15);
                $scanFullResponse                   = new ScanFullResponse();
                $scanFullResponse->website_url      = $requestUrl;
                $scanFullResponse->domain_name      = $scan['domain_name'];
                $scanFullResponse->scan_unq_id      = $uniqueId ;
                $scanFullResponse->scan_response    = json_encode($data);
                $scanFullResponse->started_at       = now();
                $scanFullResponse->save();
                $scanFullResponse_id                = $scanFullResponse->id;
                $data['brokenlink']                 = $broken_cnt;
                //insert reored in scan_res table
                $scanResponse                       = new ScanResponse();
                $scanResponse->scan_full_res_id     = $scanFullResponse_id;
                $scanResponse->is_siteup            = $data['siteup'];
                $scanResponse->ttfb                 = $data['ttfb'];
                $scanResponse->loadtime             = $data['loadtime'];
                $scanResponse->is_tls10             = $tlsscan['tls10'];
                $scanResponse->is_tls11             = $tlsscan['tls11'];
                $scanResponse->is_tls12             = $tlsscan['tls12'];
                $scanResponse->is_tls13             = $tlsscan['tls13'];
                $scanResponse->mixedcontent         = $mixedContentCount   ;
                $scanResponse->brokenlink           = $data['brokenlink'];
                $scanResponse->screenshot           = $data['screenshot'];
                $scanResponse->speed_index          = $data['speed_index'];
                $scanResponse->index_errors         = $data['index-errors'];
                $scanResponse->is_safe_browsing     = $data['safe_browsing'];
                $scanResponse->is_mobile_friendly   = $data['mobile_friendly'];
                $scanResponse->x_frame_options      = $secureHeaders['x_frame_options'];
                $scanResponse->x_xss_protection     = $secureHeaders['x_xss_protection'];
                $scanResponse->is_HSTS              = $data['HSTS'];
                $scanResponse->secure_cookie        = $data['secure_cookie'];
                $scanResponse->is_blacklist         = false;
                $scanResponse->wp_version           = $data['wp_version'];

                if ($vulnerability != null) {
                    $scanResponse->vulnerability_json       = $data['wp_vulnerability'];
                    $scanResponse->vulnerabilities_count    = count((json_decode($data['wp_vulnerability'])));
                } else {
                    $scanResponse->vulnerabilities_count    = false;
                    $scanResponse->vulnerability_json       = 'N/A';
                }
                $scanResponse->save();
                Log::info(' scan response ' . $scanResponse);
                $sslTls    = '';
                $sslTls    = trim($sslTls,",");

                if ($tlsscan['tls10']) {
                    $sslTls .=  '1.0';
                }

                if ($tlsscan['tls11']) {
                    $sslTls .=  ',' . '1.1';
                }

                if ($tlsscan['tls12']) {
                    $sslTls .=  ',' . '1.2';
                }

                if ($tlsscan['tls13']) {
                    $sslTls .=  ',' . '1.3';
                }

                $PostData = [
                    'is_siteup'                     => $data['siteup'] == true ? 'Yes' : 'No' ,
                    'loadtime'                      => str_replace("ms","",$data['loadtime']),
                    'ttfb'                          => str_replace("ms","",$data['ttfb']),
                    'is_safe_to_browse'             => $data['safe_browsing'] == true ? 'Yes' : 'No',
                    'ssl_tsl_version'               => $sslTls,
                    'domain_name'                   => $scan['domain_name'],
                    'is_mixed_content'              => isset($mixedContentCount) && $mixedContentCount == 0 ? 'No' : 'Yes',
                    'is_broken_link'                => $broken_cnt > 0 ? 'Yes' : 'No',
                    'broken_link_count'             => $broken_cnt,
                    'is_mobile_friendly'            => $data['mobile_friendly'] == false ? 'No' : 'Yes',
                    'wp_version'                    => $data['wp_version'],
                    'speed_index'                   => $data['speed_index'],
                    'is_secure_cookies'             => isset($data['secure_cookie']) && $data['secure_cookie'] != 'N/A' ? 'Yes' : 'No',
                    'is_xss_attack_protected'       => isset($data['secure_headers']['x_xss_protection']) && $data['secure_headers']['x_xss_protection'] == 'N/A' ? 'No' : 'Yes',
                    'is_x_frame_proctected'         => isset($data['secure_headers']['x_frame_options']) && $data['secure_headers']['x_frame_options'] == 'N/A' ? 'No' : 'Yes',
                    'companyemail'                  => $scan['email'],
                    'companyname'                   => substr($scan['domain_name'], 0, strrpos($scan['domain_name'], '.'))

                ];

                $PostContactData = [
                    'email'                         => $scan['email'],
                    'firstname'                     => $scan['first_name'],
                    'lastname'                      => $scan['last_name'],
                    'Tags'                          => 'contact added by scan api'

                ];
                $auth   = MauticHelper::getInstance()->pushLeadToStackk();
                $apiUrl = 'https://mymauticsite.com/api';

                if ($auth) {
                    try {
                        $api                = new MauticApi();
                        //Code to add contacts to mautic
                        $companyApi         = $api->newApi('companies', $auth, $apiUrl);
                        $company            = $companyApi->create($PostData);
                        $companyId          = $company['company']['id'];
                        $contactApi         = $api->newApi('contacts', $auth, $apiUrl);
                        $contact            = $contactApi->create($PostContactData);
                        $contactId          = $contact['contact']['id'];

                        return $response    = $companyApi->addContact($companyId, $contactId);
                    } catch (\Exception $e) {
                        return $e->getMessage();
                        Log::error('Error in Create User : ' . $e->getMessage());
                        Log::error($e->getTraceAsString());
                    }
                }
                $data['scan_id'] = $uniqueId ;
            }

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    public function failed(Throwable $exception)
    {
        Artisan::call('queue:retry all');
    }

    /**
     * @param $requestUrl
     * @return array
     */
    public function checkFeed($requestUrl)
    {
        try {
            //get wp version
            $rssFeed    = simplexml_load_file($requestUrl . "/feed/");
            $wpVersion  = "N/A";

            if (!empty($rssFeed)) {
                if (!empty($rssFeed->channel->generator)) {
                    $generator = explode('v=', $rssFeed->channel->generator);
                    $wpVersion = $generator[1];
                }
            }
            $response['success']    = true;
            $response['wp_version'] = $wpVersion;

            return $response;
        } catch (Exception $e) {
            return ['success' => false];
        }
    }

    /**
     * @param $requestUrl
     * @return array
     */
    public function checkMetaTag($requestUrl)
    {
        try {
            //get meta data
            $meta                   = get_meta_tags($requestUrl);
            $response['success']    = false;
            $response['wp_version'] = "N/A";

            if (!empty($meta['generator'])) {
                $generator              = explode(' ', $meta['generator']);
                $response['wp_version'] = $generator[1];
                $response['success']    = true;
            }

            return $response;
        } catch (Exception $e) {
            return ['success' => false];
        }
    }


    /**
     * @param $headers
     * @param $requestUrl
     * @param $googleApiKey
     * @return int
     */
    public function checkMobileResponsive($headers, $requestUrl, $googleApiKey)
    {
        try {
            $client         = new \GuzzleHttp\Client(['headers' => $headers]);
            $gglApiUrl      = 'https://searchconsole.googleapis.com/v1/urlTestingTools/mobileFriendlyTest:run?key=' . $googleApiKey;
            $body           = json_encode(['url' => $requestUrl]);

            $response       = $client->request('POST', $gglApiUrl, ['body' => $body]);

            if ($response->getStatusCode() == Response::HTTP_OK || $response->getStatusCode() == Response::HTTP_CREATED)           {
                $responseData = json_decode($response->getBody()->getContents());

                if ($responseData->mobileFriendliness == "MOBILE_FRIENDLY") {
                    return true;
                } else {
                    return false;
                }
            }

            return false;
        } catch (Exception $e) {
            Log::error($e);

            return false;
        } catch (GuzzleException $e) {
            return false;
        }

    }
}
