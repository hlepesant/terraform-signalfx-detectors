output "dnsmasq_hits" {
  description = "Detector resource for dnsmasq_hits"
  value       = signalfx_detector.dnsmasq_hits
}

output "heartbeat" {
  description = "Detector resource for heartbeat"
  value       = signalfx_detector.heartbeat
}

