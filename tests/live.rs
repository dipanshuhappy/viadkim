pub mod common;

use hickory_resolver::TokioAsyncResolver;
use viadkim::verifier::{Config, VerificationStatus};

/// Verify my signatures on a real message.
#[tokio::test]
#[ignore = "depends on live DNS records"]
async fn live_verify() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());

    let msg = make_msg();

    let (header, body) = msg.split_once("\r\n\r\n").unwrap();

    let headers = header.parse().unwrap();

    let config = Config {
        allow_expired: true,
        ..Default::default()
    };

    let sigs = common::verify(&resolver, &headers, body.as_bytes(), &config).await;

    assert_eq!(sigs.len(), 2);

    for sig in sigs {
        assert_eq!(sig.status, VerificationStatus::Success);
    }
}

fn make_msg() -> String {
    r#"Received: from mail.apache.org (mailroute1-lw-us.apache.org [207.244.88.153])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mxout1-he-de.apache.org (ASF Mail Server at mxout1-he-de.apache.org) with ESMTPS id 02D6364231
	for <dbuergin@gluet.ch>; Wed, 31 May 2023 11:52:52 +0000 (UTC)
Received: (qmail 2935341 invoked by uid 998); 31 May 2023 11:52:47 -0000
Mailing-List: contact users-help@spamassassin.apache.org; run by ezmlm
Precedence: bulk
list-help: <mailto:users-help@spamassassin.apache.org>
list-unsubscribe: <mailto:users-unsubscribe@spamassassin.apache.org>
List-Post: <mailto:users@spamassassin.apache.org>
List-Id: <users.spamassassin.apache.org>
Delivered-To: mailing list users@spamassassin.apache.org
Received: (qmail 2935322 invoked by uid 116); 31 May 2023 11:52:46 -0000
Received: from spamproc1-he-fi.apache.org (HELO spamproc1-he-fi.apache.org) (95.217.134.168)
 by apache.org (qpsmtpd/0.94) with ESMTP; Wed, 31 May 2023 11:52:46 +0000
Authentication-Results: apache.org; auth=none
Received: from localhost (localhost [127.0.0.1])
	by spamproc1-he-fi.apache.org (ASF Mail Server at spamproc1-he-fi.apache.org) with ESMTP id 9003BC07D1
	for <users@spamassassin.apache.org>; Wed, 31 May 2023 11:52:46 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at spamproc1-he-fi.apache.org
Authentication-Results: spamproc1-he-fi.apache.org (amavisd-new); dkim=neutral
	reason="invalid (unsupported algorithm ed25519-sha256)"
	header.d=gluet.ch header.b=Lvl3jVXe; dkim=pass (2048-bit key)
	header.d=gluet.ch header.b=TqDPQwlg
Received: from mx1-ec2-va.apache.org ([116.203.227.195])
	by localhost (spamproc1-he-fi.apache.org [95.217.134.168]) (amavisd-new, port 10024)
	with ESMTP id oeN70jwxylUM for <users@spamassassin.apache.org>;
	Wed, 31 May 2023 11:52:45 +0000 (UTC)
Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=46.231.204.85; helo=mail.gluet.ch; envelope-from=dbuergin@gluet.ch; receiver=<UNKNOWN> 
Received: from mail.gluet.ch (mail.gluet.ch [46.231.204.85])
	by mx1-ec2-va.apache.org (ASF Mail Server at mx1-ec2-va.apache.org) with ESMTPS id 838B4BBCB5
	for <users@spamassassin.apache.org>; Wed, 31 May 2023 11:52:44 +0000 (UTC)
DKIM-Signature: v=1; d=gluet.ch; s=ed25519.2022; a=ed25519-sha256; c=relaxed;
	t=1685533963; x=1685965963; h=In-Reply-To:References:Message-ID:Subject:To:
	From:Date:From; bh=Ok/RDBA9vdXb4/9LV6+zaL8d5k/ULQ8txPgihq+RLYo=; b=Lvl3jVXexq
	iO/XWd6fwnfh2DjqwZS4KjpCqH84seDO644qzE+3SvTCeK3X8rX7TNy4NoX/DbtweTAnSHyqWIAw=
	=
DKIM-Signature: v=1; d=gluet.ch; s=rsa.2022; a=rsa-sha256; c=relaxed;
	t=1685533963; x=1685965963; h=In-Reply-To:References:Message-ID:Subject:To:
	From:Date:From; bh=Ok/RDBA9vdXb4/9LV6+zaL8d5k/ULQ8txPgihq+RLYo=; b=TqDPQwlg53
	njF/2QvtlJhwmUgHknCdfSgGPlgA6Xf9ujD2Qwoo7f0rev/HV9cCcQIiokxzH2yq2scgRW7S3aQlT
	1nWMwTMauupENomDeI4Bu5564J/THY8pcj0WHdb3ocw/YYaHtX19TCYgsangvoBvQ2r2+ROvNCTO4
	0Ey/3ddQrvVCX0kqMoLK2S6G4T6SveN1YqtvA0J01DOR2ADXU7E+lWEjn9mVKnBsyCdFfR5IzfgP8
	+NbdhzGccyLIp7JT6MijptPw1Pqgm7Ro5a9aFS5OhQJElzj8dpEcZoXeWKHBaWRYaJm52/1MW3V0L
	t7SPHd4n5m7S78YXqRu90H2Q==
Received: from solo (unknown [IPv6:2a02:1210:1a9a:2d00:c38e:81a:5a0b:c724])
	by mail.gluet.ch (Postfix) with ESMTPSA id 5C7FC442
	for <users@spamassassin.apache.org>; Wed, 31 May 2023 13:52:43 +0200 (CEST)
Date: Wed, 31 May 2023 13:52:41 +0200
From: David =?utf-8?Q?B=C3=BCrgin?= <dbuergin@gluet.ch>
To: users@spamassassin.apache.org
Subject: Re: authres missing when ran from spamass-milter
Message-ID: <ZHc1CSNkQm3m9WII@gluet.ch>
Mail-Followup-To: users@spamassassin.apache.org
References: <ZHYhBSf+hfKW7lUu@fantomas.sk>
 <2d7e4edf-0cc6-72a3-15e5-c86fa6dba389@gluet.ch>
 <ZHYtqRk5I0vgf+lW@fantomas.sk>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: 8bit
In-Reply-To: <ZHYtqRk5I0vgf+lW@fantomas.sk>

Matus UHLAR - fantomas:
> that will need spamass-milter change.

Have you tried setting:

authres_trusted_authserv fantomas.fantomas.sk

I think this should work without changing anything in the milter …
"#
    .replace('\n', "\r\n")
}
