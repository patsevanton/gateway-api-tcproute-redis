resource "yandex_vpc_address" "addr" {
  name = "public-ip"

  external_ipv4_address {
    zone_id = yandex_vpc_subnet.k8s-subnet.zone
  }
}

// Wait on destroy so the cloud has time to release the address from dependent resources
// (e.g. load balancers) before Terraform attempts to delete it.
resource "time_sleep" "wait_before_address_deletion" {
  depends_on       = [yandex_vpc_address.addr]
  destroy_duration = var.address_destroy_wait
}

resource "yandex_dns_zone" "apatsev-org-ru" {
  name = "apatsev-org-ru-zone"

  zone   = "apatsev.org.ru."
  public = true

  private_networks = [yandex_vpc_network.k8s-network.id]
}

resource "yandex_dns_recordset" "redis1" {
  zone_id = yandex_dns_zone.apatsev-org-ru.id
  name    = "redis1.apatsev.org.ru."
  type    = "A"
  ttl     = 200
  data    = [yandex_vpc_address.addr.external_ipv4_address[0].address]

  depends_on = [yandex_vpc_address.addr]
}

resource "yandex_dns_recordset" "redis2" {
  zone_id = yandex_dns_zone.apatsev-org-ru.id
  name    = "redis2.apatsev.org.ru."
  type    = "A"
  ttl     = 200
  data    = [yandex_vpc_address.addr.external_ipv4_address[0].address]

  depends_on = [yandex_vpc_address.addr]
}

resource "yandex_dns_recordset" "postgres1" {
  zone_id = yandex_dns_zone.apatsev-org-ru.id
  name    = "postgres1.apatsev.org.ru."
  type    = "A"
  ttl     = 200
  data    = [yandex_vpc_address.addr.external_ipv4_address[0].address]

  depends_on = [yandex_vpc_address.addr]
}

resource "yandex_dns_recordset" "postgres2" {
  zone_id = yandex_dns_zone.apatsev-org-ru.id
  name    = "postgres2.apatsev.org.ru."
  type    = "A"
  ttl     = 200
  data    = [yandex_vpc_address.addr.external_ipv4_address[0].address]

  depends_on = [yandex_vpc_address.addr]
}

output "gateway_ip" {
  description = "Статический IP адрес для Envoy Gateway LoadBalancer"
  value       = yandex_vpc_address.addr.external_ipv4_address[0].address
}
