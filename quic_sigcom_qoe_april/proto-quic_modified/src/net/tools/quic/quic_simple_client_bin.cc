// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "url/gurl.h"

#define __HONEST_PERFORMANCE_CHECK__
#ifdef __HONEST_PERFORMANCE_CHECK__
#include <time.h>
#include <sys/time.h>

#include "net/quic/core/quic_utils.h"

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif
#endif // __HONEST_PERFORMANCE_CHECK__

using base::StringPiece;
using net::CertVerifier;
using net::CTPolicyEnforcer;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using net::ProofVerifier;
using net::ProofVerifierChromium;
using net::QuicTextUtils;
using net::SpdyHeaderBlock;
using net::TransportSecurityState;
using std::cout;
using std::cerr;
using std::endl;
using std::string;


// HONEST added below for debugging
#if 1
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
extern char g_honest_buf[80*1024*1024];
extern uint64_t g_honest_buf_idx;
void honest_sigint_handler(int s) {
  g_honest_buf[g_honest_buf_idx++] = '\n';
  g_honest_buf[g_honest_buf_idx] = 0; 
  FILE* fp = fopen("c.txt", "w");
  if(fp) {
    fwrite(g_honest_buf, g_honest_buf_idx,1, fp);
	// fprintf(fp, "%s", g_honest_buf);
    fclose(fp);
	fp = NULL;
  } else {
	cout << "fopen fails" << endl;
  }
  exit(1);
}
#endif

// The IP or hostname the quic client will connect to.
string FLAGS_host = "";
// The port to connect to.
int32_t FLAGS_port = 0;
// If set, send a POST with this body.
string FLAGS_body = "";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
string FLAGS_headers = "";
// Set to true for a quieter output experience.
bool FLAGS_quiet = true;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;

#ifdef __HONEST_PERFORMANCE_CHECK__
int32_t FLAGS_iteration_num = 1;
int32_t FLAGS_unit = 1;
int32_t FLAGS_interval_msec = 0;
#endif // __HONEST_PERFORMANCE_CHECK__

class FakeProofVerifier : public ProofVerifier {
 public:
  net::QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      net::QuicVersion quic_version,
      StringPiece chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const net::ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<net::ProofVerifyDetails>* details,
      std::unique_ptr<net::ProofVerifierCallback> callback) override {
    return net::QUIC_SUCCESS;
  }

  net::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const std::vector<std::string>& certs,
      const net::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<net::ProofVerifyDetails>* verify_details,
      std::unique_ptr<net::ProofVerifierCallback> callback) override {
    return net::QUIC_SUCCESS;
  }
};

#ifdef __HONEST_PERFORMANCE_CHECK__
bool honest_get_time(timespec& ts)
{
#ifdef __MACH__ // OS X does not have clock_gettime, use clock_get_time
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	ts.tv_sec = mts.tv_sec;
	ts.tv_nsec = mts.tv_nsec;
#else
	clock_gettime(CLOCK_REALTIME, &ts);
#endif
	return true;
}
#endif // __HONEST_PERFORMANCE_CHECK__
int main(int argc, char* argv[]) {
  // HONEST added below for debugging
  struct sigaction sig_int_handler;
  sig_int_handler.sa_handler = honest_sigint_handler;
  sigemptyset(&sig_int_handler.sa_mask);
  sig_int_handler.sa_flags = 0;
  sigaction(SIGINT, &sig_int_handler, NULL);

  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& urls = line->GetArgs();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));
  net::QuicUtils::honest_conf_setup();
  if (line->HasSwitch("h") || line->HasSwitch("help") || urls.empty()) {
    const char* help_str =
        "Usage: quic_client [options] <url>\n"
        "\n"
        "<url> with scheme must be provided (e.g. http://www.google.com)\n\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--host=<host>               specify the IP address of the hostname to "
        "connect to\n"
        "--port=<port>               specify the port to connect to\n"
        "--body=<body>               specify the body to post\n"
        "--body_hex=<body_hex>       specify the body_hex to be printed out\n"
        "--headers=<headers>         specify a semicolon separated list of "
        "key:value pairs to add to request headers\n"
        "--quiet                     specify for a quieter output experience\n"
        "--quic-version=<quic version> specify QUIC version to speak\n"
        "--version_mismatch_ok       if specified a version mismatch in the "
        "handshake is not considered a failure\n"
        "--redirect_is_success       if specified an HTTP response code of 3xx "
        "is considered to be a successful response, otherwise a failure\n"
        "--initial_mtu=<initial_mtu> specify the initial MTU of the connection"
        "\n"
        "--disable-certificate-verification do not verify certificates\n"
        "--iteration_num \n"
        "--unit 1(ms),2(us),3(ns)\n"
        "--interval <>ms\n";
    cout << help_str;
    exit(0);
  }
  if (line->HasSwitch("host")) {
    FLAGS_host = line->GetSwitchValueASCII("host");
  }
  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      std::cerr << "--port must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("body")) {
    FLAGS_body = line->GetSwitchValueASCII("body");
  }
  if (line->HasSwitch("body_hex")) {
    FLAGS_body_hex = line->GetSwitchValueASCII("body_hex");
  }
  if (line->HasSwitch("headers")) {
    FLAGS_headers = line->GetSwitchValueASCII("headers");
  }
  if (line->HasSwitch("quiet")) {
    FLAGS_quiet = true;
  }
  if (line->HasSwitch("quic-version")) {
    int quic_version;
    if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
                          &quic_version)) {
      FLAGS_quic_version = quic_version;
    }
  }
  if (line->HasSwitch("version_mismatch_ok")) {
    FLAGS_version_mismatch_ok = true;
  }
  if (line->HasSwitch("redirect_is_success")) {
    FLAGS_redirect_is_success = true;
  }
  if (line->HasSwitch("initial_mtu")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("initial_mtu"),
                           &FLAGS_initial_mtu)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
  }
#ifdef __HONEST_PERFORMANCE_CHECK__
  if (line->HasSwitch("iteration_num")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("iteration_num"),
                           &FLAGS_iteration_num)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("unit")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("unit"),
                           &FLAGS_unit)) {
      std::cerr << "--unit\n";
      return 1;
    }
  }
  if (line->HasSwitch("interval_msec")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("interval_msec"),
                           &FLAGS_interval_msec)) {
      std::cerr << "--interval_msec\n";
      return 1;
    }
  }
#endif //__HONEST_PERFORMANCE_CHECK__

#ifndef __HONEST_PERFORMANCE_CHECK__
  VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
#else
  cout << "server host: " << FLAGS_host << " port: " << FLAGS_port
#endif
          << " body: " << FLAGS_body << " headers: " << FLAGS_headers
          << " quiet: " << FLAGS_quiet
          << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " redirect_is_success: " << FLAGS_redirect_is_success
#ifndef __HONEST_PERFORMANCE_CHECK__
          << " initial_mtu: " << FLAGS_initial_mtu << endl;
#else
          << " initial_mtu: " << FLAGS_initial_mtu
          << " iteration_num: " << FLAGS_iteration_num 
          << " unit: " << FLAGS_unit  
          << " interval_msec: " << FLAGS_interval_msec << endl;
#endif // __HONEST_PERFORMANCE_CHECK__

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  net::QuicIpAddress ip_addr;

  GURL url(urls[0]);
  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.EffectiveIntPort();
  }
  if (!ip_addr.FromString(host)) {
    net::AddressList addresses;
    int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
    if (rv != net::OK) {
      LOG(ERROR) << "Unable to resolve '" << host
                 << "' : " << net::ErrorToShortString(rv);
      return 1;
    }
    ip_addr =
        net::QuicIpAddress(net::QuicIpAddressImpl(addresses[0].address()));
  }

  string host_port = net::QuicStrCat(ip_addr.ToString(), ":", port);
  VLOG(1) << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  net::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                              net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::AllSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(static_cast<net::QuicVersion>(FLAGS_quic_version));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
  ct_verifier->AddLogs(net::ct::CreateLogVerifiersForKnownLogs());
  std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
  std::unique_ptr<ProofVerifier> proof_verifier;
  if (line->HasSwitch("disable-certificate-verification")) {
    proof_verifier.reset(new FakeProofVerifier());
  } else {
    proof_verifier.reset(new ProofVerifierChromium(
        cert_verifier.get(), ct_policy_enforcer.get(),
        transport_security_state.get(), ct_verifier.get()));
  }
  net::QuicSimpleClient client(net::QuicSocketAddress(ip_addr, port), server_id,
                               versions, std::move(proof_verifier));
#if 0
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize); // HONEST no longer use
#else
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::QuicUtils::honest_DefaultMaxPacketSize); // HONEST
#endif
  if (!client.Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    net::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << QuicVersionVectorToString(versions) << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << net::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.host();
  header_block[":path"] = url.path();

  // Append any additional headers supplied on the command line.
  for (StringPiece sp : QuicTextUtils::Split(FLAGS_headers, ';')) {
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<StringPiece> kv = QuicTextUtils::Split(sp, ':');
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client.set_store_response(true);

  // Send the request.
#ifdef __HONEST_PERFORMANCE_CHECK__
  int cnt = 0;
  uint64_t diff;
  struct timespec start, end; 
  #define BILLION 1000000000L
  #define MILLION 1000000
  #define THOUSAND 1000
  while(FLAGS_iteration_num > cnt++) {
	  honest_get_time(start);
	  client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);
	  cout << "(" << cnt << "\t/" << FLAGS_iteration_num << ") ";
          if(FLAGS_interval_msec == 0)
            usleep(FLAGS_interval_msec*1000);
#else
	  client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);
         
#endif
	  // Print request and response details.
	  if (!FLAGS_quiet) {
		  cout << "Request:" << endl;
		  cout << "headers:" << header_block.DebugString();
		  if (!FLAGS_body_hex.empty()) {
			  // Print the user provided hex, rather than binary body.
			  cout << "body:\n"
				  << QuicTextUtils::HexDump(QuicTextUtils::HexDecode(FLAGS_body_hex))
				  << endl;
		  } else {
			  cout << "body: " << body << endl;
		  }
		  cout << endl;
		  cout << "Response:" << endl;
		  cout << "headers: " << client.latest_response_headers() << endl;
		  string response_body = client.latest_response_body();
		  if (!FLAGS_body_hex.empty()) {
			  // Assume response is binary data.
			  cout << "body:\n" << QuicTextUtils::HexDump(response_body) << endl;
		  } else {
			  cout << "body: " << response_body << endl;
		  }
		  cout << "trailers: " << client.latest_response_trailers() << endl;
	  }

	  size_t response_code = client.latest_response_code();
#ifdef __HONEST_PERFORMANCE_CHECK__
	  honest_get_time(end);
	  switch(FLAGS_unit) {
		  case 1:
			  diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			  cout << "Elapsed time = " << (long long unsigned int)diff/MILLION << " ms. ";
			  break;
		  case 2:
			  diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			  cout << "Elapsed time = " << (long long unsigned int)diff/THOUSAND << " us. ";
			  break;
		  case 3:
			  diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			  cout << "Elapsed time = " << (long long unsigned int)diff << " ns. ";
			  break;
		  default:
			  break;
	  }
#endif

	  if (response_code >= 200 && response_code < 300) {
		  cout << "Request succeeded (" << response_code << ")." << endl;
	  } else if (response_code >= 300 && response_code < 400) {
		  if (FLAGS_redirect_is_success) {
			  cout << "Request succeeded (redirect " << response_code << ")." << endl;
		  } else {
			  cout << "Request failed (redirect " << response_code << ")." << endl;
		  }
	  } else {
		  cerr << "Request failed (" << response_code << ")." << endl;
	  }
#ifdef __HONEST_PERFORMANCE_CHECK__
  }
#endif
}
