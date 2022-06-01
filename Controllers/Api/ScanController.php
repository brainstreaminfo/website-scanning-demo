<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Jobs\ScanTools;
use App\Models\ScanFullResponse;
use App\Models\ScanResponse;
use App\Models\Vulnerability;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Class ScanController
 * @package App\Http\Controllers\Api
 */
class ScanController extends Controller
{
    /**
     * @param Request $request
     * @return Exception|\Exception|\Illuminate\Http\JsonResponse
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function checkTools(Request $request)
    {
        try {
            $input          = $request->all();
            //website url which need to verify
            $requestUrl     = $input['url'];
            $apiKey         = 'abcd123!@#';
            $gfApiUrl       = 'example.com';
            $data           = [];
            //headers for APIs
            $headers = [
                'content-type'      => 'application/json',
                'x-rapidapi-host'   => 'example.com',
                'x-rapidapi-key'    => $apiKey
            ];
            //example endpoints list
            $endpointsList = ['up', 'ttfb', 'loadtime', 'tlsscan', 'mixedcontent', 'brokenlink', 'screenshot', 'lighthouse'];

            foreach ($endpointsList as $singleReq) {
                $client         = new \GuzzleHttp\Client(['headers' => $headers]);
                $body           = json_encode(['url' => $requestUrl]);
                $response       = $client->request('POST', $gfApiUrl . $singleReq, ['body' => $body]);

                if ($response->getStatusCode() == Response::HTTP_OK || $response->getStatusCode() == Response::HTTP_CREATED) {
                    $responseData = json_decode($response->getBody()->getContents());

                    switch ($singleReq) {
                        case "up":
                            if ($responseData->data[0]->description == "Site is up.") {
                                $data['siteup'] = false;
                            } else {
                                $data['siteup'] = true;
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
                            $tlsscan['tls10'] = ($responseData->data->protocols->tls10) ? false : true;
                            $tlsscan['tls11'] = ($responseData->data->protocols->tls11) ? false : true;
                            $tlsscan['tls12'] = ($responseData->data->protocols->tls12) ? false : true;
                            $tlsscan['tls13'] = ($responseData->data->protocols->tls13) ? false : true;
                            $data['tlsscan']  = $tlsscan;

                            break;
                        case "mixedcontent":
                            $data['mixedcontent']   = $responseData;
                            $mixedContentCount      = false;

                            if ($responseData->message == 'Mixed content(s) found.') {
                                if (isset($responseData->data->insecure)) {
                                    $mixedContentCount = count($responseData->data->insecure);
                                }
                            }

                            break;
                        case "brokenlink":
                            $brokenCnt     = false;
                            $brokenLinks   = [];

                            if (isset($responseData->data)) {
                                foreach ($responseData->data as $broken) {
                                    if ($broken->status != Response::HTTP_OK) {
                                        $brokenLinks[]  = json_encode($broken);
                                        $brokenCnt      = $brokenCnt + 1;
                                    }
                                }
                            }
                            $data['brokenlink']['brokenlink_count'] = $brokenCnt;
                            $data['brokenlink']['data']             = $brokenLinks;

                            break;
                        case "screenshot":
                            $data['screenshot'] = $responseData->data[0]->screenshot;

                            break;
                        case "lighthouse":
                            $fileLink      = $responseData->data;
                            $client        = new \GuzzleHttp\Client();
                            $res           = $client->request('GET', $fileLink);
                            $fileStr       = utf8_encode($res->getBody()->getContents());
                            $fileResult    = json_decode($fileStr, true);

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

                            if ($fileResult['audits']['is-crawlable']['title'] != "Page isn’t blocked from indexing") {
                                $data['crawl-errors'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $fileResult['audits']['is-crawlable']['score']);
                            } else {
                                $data['crawl-errors'] = false;
                            }

                            if ($fileResult['audits']['robots-txt'] != "robots.txt is valid") {
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
            $googleApiKey   = env('GOOGLE_API_KEY');
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
            $body         = json_encode($body);
            $response     = $client->request('POST', $gglApiUrl, ['body' => $body]);

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
            $secureHeaders              = [
                                            'strict_transport_security'         => "N/A",
                                            'public_key_pins'                   => "N/A",
                                            'content_security_policy'           => "N/A",
                                            'referrer_policy'                   => "N/A",
                                            'expect_ct'                         => "N/A",
                                            'feature_policy'                    => "N/A",
                                            'x_frame_options'                   => "N/A",
                                            'x_xss_protection'                  => "N/A",
                                            'x_content_type_options'            => "N/A",
                                            'x_permitted_cross_domain_policies' => "N/A"
                                        ];
            $xFrameOptions              = "N/A";
            $hsts                       = "N/A";
            $xXssProtection             = "N/A";
            $csp                        = "N/A";
            $crossDomainPolicy          = "N/A";
            $secure_cookie              = "N/A";

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
                    $xFrameOptions                     = trim(str_replace('X-Frame-Options:', '', $header));
                    $secureHeaders['x_frame_options']  = trim(str_replace('X-Frame-Options:', '', $header));
                }

                if (strpos($header, 'Strict-Transport-Security') !== false) {
                    $hsts                                          = trim(str_replace('Strict-Transport-Security:', '', $header));
                    $secureHeaders['strict_transport_security']    = trim(str_replace('Strict-Transport-Security:', '', $header));
                }

                if (strpos($header, 'X-XSS-Protection') !== false) {
                    $xXssProtection                    = trim(str_replace('X-XSS-Protection:', '', $header));
                    $secureHeaders['x_xss_protection'] = "available";
                }

                if (strpos($header, 'Content-Security-Policy') !== false) {
                    $csp = trim(str_replace('Content-Security-Policy:', '', $header));
                    $secureHeaders['content_security_policy'] = trim(str_replace('Content-Security-Policy:', '', $header));
                }

                if (strpos($header, 'X-Permitted-Cross-Domain-Policies') !== false) {
                    $crossDomainPolicy   = trim(str_replace('X-Permitted-Cross-Domain-Policies:', '', $header));
                }

                if (strpos($header, 'set-cookie') !== false) {
                    $secure_cookie = trim(str_replace('set-cookie:', '', $header));
                }
            }
            $data['secure_headers']     = $secureHeaders;
            $data['x_frame_options']    = $xFrameOptions;
            $data['HSTS']               = ($hsts != "N/A") ? true : false;
            $data['x-xss-protection']   = $xXssProtection  ;
            $data['secure_cookie']      = $secure_cookie;
            $meta                       = $this->checkMetaTag($requestUrl);
            $feed                       = $this->checkFeed($requestUrl);

            if ($feed['success']) {
                $data['wp_version'] = $feed['wp_version'];
            } elseif ($meta['success']) {
                $data['wp_version'] = $meta['wp_version'];
            } else {
                $data['wp_version'] = 'N/A';
            }

            //get wp_vulnerability
            $vulnerability = null;
            if ($data['wp_version'] != 'N/A') {
                $wpMainVersion = floatval(substr($data['wp_version'], 0, 3));
                ($wpMainVersion <= 5.0) ? $checkWpVersion = "5.0" : $checkWpVersion = $wpMainVersion;
                $vulnerability = Vulnerability::select('vulnerabilities')->where('wp_version', $checkWpVersion)->first();
            }

            if ($vulnerability != null) {
                $data['wp_vulnerability'] = $vulnerability->vulnerabilities;
                $data['wp_vulnerability'] = trim($data['wp_vulnerability'], '"');
            } else {
                $data['wp_vulnerability'] = 'N/A';
            }

            //insert reored in scan_full_res table
            $uniqueId                               = Str::random(15);
            $scanFullResponse                       = new ScanFullResponse();
            $scanFullResponse->website_url          = $requestUrl;
            $scanFullResponse->scan_unq_id          = $uniqueId;
            $scanFullResponse->scan_response        = json_encode($data);
            $scanFullResponse->save();
            $scanFullResponse_id                    = $scanFullResponse->id;
            $data['brokenlink']                     = $brokenCnt;
            //insert reored in scan_res table
            $scanResponse                           = new ScanResponse();
            $scanResponse->scan_full_res_id         = $scanFullResponse_id;
            $scanResponse->is_siteup                = $data['siteup'];
            $scanResponse->ttfb                     = $data['ttfb'];
            $scanResponse->loadtime                 = $data['loadtime'];
            $scanResponse->is_tls10                 = $tlsscan['tls10'];
            $scanResponse->is_tls11                 = $tlsscan['tls11'];
            $scanResponse->is_tls12                 = $tlsscan['tls12'];
            $scanResponse->is_tls13                 = $tlsscan['tls13'];
            $scanResponse->mixedcontent             = $mixedContentCount;
            $scanResponse->brokenlink               = $data['brokenlink'];
            $scanResponse->screenshot               = $data['screenshot'];
            $scanResponse->speed_index              = $data['speed_index'];
            $scanResponse->index_errors             = $data['index-errors'];
            $scanResponse->is_safe_browsing         = $data['safe_browsing'];
            $scanResponse->is_mobile_friendly       = $data['mobile_friendly'];
            $scanResponse->x_frame_options          = $secureHeaders['x_frame_options'];
            $scanResponse->x_xss_protection         = $secureHeaders['x_xss_protection'];
            $scanResponse->is_HSTS                  = $data['HSTS'];
            $scanResponse->secure_cookie            = $data['secure_cookie'];
            $scanResponse->is_blacklist             = false;
            $scanResponse->wp_version               = $data['wp_version'];
            $data['scan_id']                        = $uniqueId;
            $data['mixedcontent']                   = $mixedContentCount;

            if ($vulnerability != null) {
                $scanResponse->vulnerability_json       = $data['wp_vulnerability'];
                $scanResponse->vulnerabilities_count    = count((json_decode($data['wp_vulnerability'])));
            } else {
                $scanResponse->vulnerabilities_count    = false;
                $scanResponse->vulnerability_json       = 'N/A';
            }
            $scanResponse->save();

            return response()->json(['success' => true, 'data' => $data], Response::HTTP_OK);
        } catch (Exception $e) {
            return $e;
        }
    }

    /**
     * @param $headers
     * @param $requestUrl
     * @param $googleApiKey
     * @return int
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function checkMobileResponsive($headers, $requestUrl, $googleApiKey)
    {
        try {
            $client         = new \GuzzleHttp\Client(['headers' => $headers]);
            $gglApiUrl      = 'https://searchconsole.googleapis.com/v1/urlTestingTools/mobileFriendlyTest:run?key=' . $googleApiKey;
            $body           = json_encode(['url' => $requestUrl]);
            $response       = $client->request('POST', $gglApiUrl, ['body' => $body]);

            if ($response->getStatusCode() == Response::HTTP_OK  || $response->getStatusCode() == Response::HTTP_CREATED) {
                $responseData = json_decode($response->getBody()->getContents());

                if ($responseData->mobileFriendliness == "MOBILE_FRIENDLY") {
                    return true;
                } else {
                    return false;
                }
            }

            return false;
        } catch (\Exception $e) {
            return false;
        }

    }

    /**
     * @param $url
     * @return mixed
     */
    public function removeHttp($url)
    {
        $disallowed = ['http://', 'https://'];

        foreach ($disallowed as $d) {
            if (strpos($url, $d) == true) {
                return str_replace($d, '', $url);
            }
        }

        return $url;
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
        } catch (\Exception $e) {
            return ['success' => false];
        }
    }

    /**
     * @param $requestUrl
     * @return array
     */
    public function checkFeed($requestUrl)
    {
        try {
            //get wp version
            $rssFeed        = simplexml_load_file($requestUrl . "/feed/");
            $wpVersion      = "N/A";

            if (!empty($rssFeed)) {
                if (!empty($rssFeed->channel->generator)) {
                    $generator  = explode('v=', $rssFeed ->channel->generator);
                    $wpVersion  = $generator[1];
                }
            }
            $response['success']    = true;
            $response['wp_version'] = $wpVersion ;

            return $response;
        } catch (\Exception $e) {
            return ['success' => false];
        }
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkToolsQueue(Request $request)
    {
        $input      = $request->all();
        $data       = [];
        $scanData   = [];
        $queues     = DB::table('jobs')->get();

        foreach ($input['url'] as $key => $url) {
            $isQueued                      = true;
            $domainName                    = $this->removeHttpWww($url);
            $scanData[$key]['url']         = $url;
            $scanData[$key]['domain_name'] = $domainName ;
            $scanData[$key]['email']       = $input['email'];
            $scanData[$key]['first_name']  = $input['first_name'];
            $scanData[$key]['last_name']   = $input['last_name'];
            $checkEntry = ScanFullResponse::where('domain_name', $domainName)
                        ->where('started_at', '>=', Carbon::now()->subdays(2))
                        ->count();

            foreach ($queues as $queue) {
                $payload = json_decode($queue->payload);

                if (isset($payload->data->command)) {
                    if (strpos($payload->data->command, $url) != false) {
                        $isQueued  = false;
                    }
                }
            }

            if ($checkEntry == false && $isQueued) {
                dispatch(new ScanTools($scanData));
                $data[$url] = 'Your website is scanning.';
            } else {
                $data[$url] = 'Your website scanned successfully, You can get result.';
            }
        }

        return response()->json(['success' => true, 'data' => $data, 'Message' => 'Scan request completed.'], Response::HTTP_OK);
    }

    /**
     * @param $url
     * @return string|string[]|null
     */
    public function removeHttpWww($url)
    {
        $urlParts       = parse_url($url);
        // Remove www.
        $domainName     = preg_replace('/^www\./', '', $urlParts['host']);

        return $domainName ;
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function getScanResult(Request $request)
    {
        $input      = $request->all();
        $data       = [];
        $scanData   = [];
        $queues     = DB::table('jobs')->get();

        foreach ($input['url'] as $key => $url) {
            $isQueued                           = false;
            $domainName                         = $this->removeHttpWww($url);
            $scanData[$key]['url']              = $url;
            $scanData[$key]['domain_name']      = $domainName ;
            $checkEntry = ScanFullResponse::select('id', 'scan_response')
                        ->where('domain_name', $domainName)
                        ->where('started_at', '>=', Carbon::now()->subdays(2))
                        ->first();

            foreach ($queues as $queue) {
                $payload = json_decode($queue->payload);

                if (isset($payload->data->command)) {
                    if (strpos($payload->data->command, $url) != false) {
                        $isQueued  = true;
                    }
                }
            }

            if ($checkEntry != null) {
                $data[$url]     = json_decode($checkEntry->scan_response);
                $vulnerability  = json_decode($checkEntry->scan_response);

                if (!empty($vulnerability)) {
                    $vulnerability                  = trim($vulnerability->wp_vulnerability, '"');
                    $data['vulnerabilities_count']  = is_array(json_decode($vulnerability)) ? count((json_decode($vulnerability))) : 0;
                }
            } else {
                if (!$isQueued) {
                    dispatch(new ScanTools($scanData));
                }
                $data[$url] = 'Your website is scanning please try after some time.';
            }
        }

        return response()->json(['success' => true, 'data' => $data, 'Message' => 'Scan request completed.'], Response::HTTP_OK);
    }

}

