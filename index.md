# Domain Control with Packet Filtering, NAT, WAF, DMZ

## MỤC LỤC

- [1. Domain Control](#1-domain-control)
  - [1.1. Định nghĩa](#11-định-nghĩa)
    - [a) Domain](#a-domain)
    - [b) Domain Controller](#b-domain-controller)
  - [1.2. Vai trò](#12-vai-trò)
    - [a) Global Catalog Server](#a-global-catalog-server)
    - [b) Operation Master](#b-operation-master)
- [2. Domain Control with Packet Filtering](#2-domain-control-with-packet-filtering)
  - [2.1. Định nghĩa](#21-định-nghĩa)
  - [2.2. Cơ chế](#22-cơ-chế)
  - [2.3. Demo](#23-demo)
- [3. Domain Control with NAT](#3-domain-control-with-nat)
  - [3.1. Khái niệm NAT](#31-khái-niệm-nat)
  - [3.2. Cơ chế NAT Firewall](#32-cơ-chế-nat-firewall)
  - [3.3. Demo](#33-demo)
    - [Ví dụ đầu tiên](#ví-dụ-đầu-tiên)
- [4. Domain Control with WAF](#4-domain-control-with-waf)
  - [4.1. Định nghĩa](#41-định-nghĩa)
  - [4.2. Mục đích sử dụng](#42-mục-đích-sử-dụng)
  - [4.3. Cơ chế](#43-cơ-chế)
  - [4.4. Các loại WAF](#44-các-loại-waf)
  - [4.5. Demo](#45-demo)
- [5. Domain Control with DMZ](#5-domain-control-with-dmz)
  - [5.1. Khái niệm DMZ (Demilitarized Zone)](#51-khái-niệm-dmz-demilitarized-zone)
  - [5.2. Cơ chế](#52-cơ-chế)
  - [5.3. Demo](#53-demo)
- [6. Tổng kết](#6-tổng-kết)
- [7. References](#7-references)
<!-- - [8. Contributors](#8-contributors) -->

## 1. Domain Control

### 1.1. Định nghĩa

#### a) Domain

Domain là một mô tả tập hợp tất cả người dùng, máy chủ, hệ thống dữ liệu, mạng internet hay các tài nguyên bất kỳ được quản lý theo nguyên tắc chung. Một domain có thể có nhiều domain controller.

#### b) Domain Controller

Domain controller là một hệ thống máy chủ được thiết lập với mục đích quản lý hay kiểm tra một tên miền bất kỳ nào đó.

Domain controller hoạt động tương tự như một người gác cổng chịu trách nhiệm xác thực và ủy quyền user cũng như quản lý an ninh mạng và những vấn đề khác có liên quan đến dữ liệu.

Cách sử dụng: Toàn bộ Request của User sẽ được chuyển đến Domain Controller để được xác thực và ủy quyền. Trước khi truy cập theo Request tương ứng thì người dùng cần xác nhận danh tính của bản thân

### 1.2. Vai trò
