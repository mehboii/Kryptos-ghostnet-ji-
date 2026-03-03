±e// Initialize Theme Toggle and Animations
document.addEventListener('DOMContentLoaded', () => {
    // 1. Theme Toggle
    const themeToggleBtn = document.getElementById('theme-toggle');
    const htmlElement = document.documentElement;

    // Check local storage or system preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        htmlElement.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        htmlElement.setAttribute('data-theme', 'dark');
        updateThemeIcon('dark');
    }

    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = htmlElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        htmlElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });

    function updateThemeIcon(theme) {
        const iconContainer = themeToggleBtn;
        if (theme === 'dark') {
            // Moon icon
            iconContainer.innerHTML = `<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" class="moon-icon"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;
        } else {
            // Sun icon
            iconContainer.innerHTML = `<svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" class="sun-icon"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
        }
    }

    // 2. Metrics Counter Animation Engine
    const counters = document.querySelectorAll('.counter');
    const runCounters = () => {
        counters.forEach(counter => {
            if (counter.classList.contains('counted')) return;
            counter.classList.add('counted');
            const target = +counter.getAttribute('data-target');
            const duration = 2000; // ms
            const fps = 60;
            const frames = Math.round(duration / (1000 / fps));
            const increment = target / frames;
            let current = 0;
            const isFloat = counter.getAttribute('data-target').includes('.');
            const updateCounter = () => {
                current += increment;
                if (current < target) {
                    counter.innerText = isFloat ? current.toFixed(2) : Math.ceil(current).toLocaleString();
                    requestAnimationFrame(updateCounter);
                } else {
                    counter.innerText = isFloat ? target.toFixed(2) : target.toLocaleString();
                }
            };
            updateCounter();
        });
    };

    // 3. Simple Intersection Observer for Reveal and Counters
    const observerOptions = { threshold: 0.1, rootMargin: "0px 0px -50px 0px" };
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                if (entry.target.id === 'metrics' || entry.target.classList.contains('metrics-section')) {
                    runCounters();
                }
            }
        });
    }, observerOptions);

    const reveals = document.querySelectorAll('.reveal');
    reveals.forEach(el => observer.observe(el));

    // Explicitly observe metrics section
    const metricsSection = document.getElementById('metrics');
    if (metricsSection) observer.observe(metricsSection);

    // Initial Hero Section Reveal Delay
    setTimeout(() => {
        const heroReveals = document.querySelectorAll('.hero-content.reveal');
        heroReveals.forEach(el => el.classList.add('active'));
    }, 150);

    // 4. Smooth Anchor Scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;

            const targetEl = document.querySelector(targetId);
            if (targetEl) {
                e.preventDefault();
                targetEl.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // 5. Navbar Blur on Scroll
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
});

// 5. Three.js Network Mesh Animation
// Implemented immediately logic to make it responsive
function initThreeJS() {
    const container = document.getElementById('hero-canvas-container');
    if (!container) return;

    // Scene setup
    const scene = new THREE.Scene();

    // Camera setup
    const camera = new THREE.PerspectiveCamera(75, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.z = 150;

    // Renderer setup
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Particles/Nodes Configuration
    const particleCount = 200;
    const particles = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const velocities = [];

    const r = 180;
    for (let i = 0; i < particleCount; i++) {
        positions[i * 3] = (Math.random() - 0.5) * r;
        positions[i * 3 + 1] = (Math.random() - 0.5) * r;
        positions[i * 3 + 2] = (Math.random() - 0.5) * r;

        velocities.push({
            x: (Math.random() - 0.5) * 0.2,
            y: (Math.random() - 0.5) * 0.2,
            z: (Math.random() - 0.5) * 0.2
        });
    }

    particles.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    // Particle Material
    const pMaterial = new THREE.PointsMaterial({
        color: 0x4f8cff,
        size: 2.5,
        blending: THREE.AdditiveBlending,
        transparent: true,
        opacity: 0.8
    });

    const particleSystem = new THREE.Points(particles, pMaterial);
    scene.add(particleSystem);

    // Lines Configuration
    const lineMaterial = new THREE.LineBasicMaterial({
        color: 0x2addc4,
        transparent: true,
        opacity: 0.15
    });

    // Creating initial connection lines buffer
    // Max lines = particleCount * particleCount (but we limit connections)
    const maxConnections = 600;
    const lineGeometry = new THREE.BufferGeometry();
    const linePositions = new Float32Array(maxConnections * 3 * 2);
    lineGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
    // Important: telling Three.js not to bound lines initially to prevent clipping
    lineGeometry.setDrawRange(0, 0);

    const linesMesh = new THREE.LineSegments(lineGeometry, lineMaterial);
    scene.add(linesMesh);

    // Mouse Interaction
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const windowHalfX = window.innerWidth / 2;
    const windowHalfY = window.innerHeight / 2;

    document.addEventListener('mousemove', (event) => {
        mouseX = (event.clientX - windowHalfX) * 0.05;
        mouseY = (event.clientY - windowHalfY) * 0.05;
    });

    // Raycaster for hover interactions
    const raycaster = new THREE.Raycaster();
    const mouseParams = new THREE.Vector2();

    container.addEventListener('mousemove', (event) => {
        const rect = container.getBoundingClientRect();
        mouseParams.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        mouseParams.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    });

    const maxDistance = 40;

    // Animation Loop
    let animationFrameId;

    function animate() {
        animationFrameId = requestAnimationFrame(animate);

        targetX = mouseX * 0.5;
        targetY = mouseY * 0.5;

        // Smooth camera movement
        scene.rotation.x += 0.001;
        scene.rotation.y += 0.002;

        camera.position.x += (mouseX * 0.5 - camera.position.x) * 0.05;
        camera.position.y += (-mouseY * 0.5 - camera.position.y) * 0.05;
        camera.lookAt(scene.position);

        // Update particle positions
        let vertexpos = 0;
        let colorpos = 0;
        let numConnected = 0;

        const posAttr = particleSystem.geometry.attributes.position;
        const lineAttr = linesMesh.geometry.attributes.position;

        // Update physics
        for (let i = 0; i < particleCount; i++) {

            velocities[i].x += (Math.random() - 0.5) * 0.01;
            velocities[i].y += (Math.random() - 0.5) * 0.01;
            velocities[i].z += (Math.random() - 0.5) * 0.01;

            // Apply friction
            velocities[i].x *= 0.99;
            velocities[i].y *= 0.99;
            velocities[i].z *= 0.99;

            posAttr.array[i * 3] += velocities[i].x;
            posAttr.array[i * 3 + 1] += velocities[i].y;
            posAttr.array[i * 3 + 2] += velocities[i].z;

            // Bounding box reset
            const bounds = r / 2;
            if (posAttr.array[i * 3] < -bounds || posAttr.array[i * 3] > bounds) velocities[i].x *= -1;
            if (posAttr.array[i * 3 + 1] < -bounds || posAttr.array[i * 3 + 1] > bounds) velocities[i].y *= -1;
            if (posAttr.array[i * 3 + 2] < -bounds || posAttr.array[i * 3 + 2] > bounds) velocities[i].z *= -1;
        }

        posAttr.needsUpdate = true;

        // Draw connections dynamically
        for (let i = 0; i < particleCount; i++) {
            for (let j = i + 1; j < particleCount; j++) {
                const dx = posAttr.array[i * 3] - posAttr.array[j * 3];
                const dy = posAttr.array[i * 3 + 1] - posAttr.array[j * 3 + 1];
                const dz = posAttr.array[i * 3 + 2] - posAttr.array[j * 3 + 2];
                const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);

                if (dist < maxDistance && numConnected < maxConnections) {

                    lineAttr.array[vertexpos++] = posAttr.array[i * 3];
                    lineAttr.array[vertexpos++] = posAttr.array[i * 3 + 1];
                    lineAttr.array[vertexpos++] = posAttr.array[i * 3 + 2];

                    lineAttr.array[vertexpos++] = posAttr.array[j * 3];
                    lineAttr.array[vertexpos++] = posAttr.array[j * 3 + 1];
                    lineAttr.array[vertexpos++] = posAttr.array[j * 3 + 2];

                    numConnected++;
                }
            }
        }

        linesMesh.geometry.setDrawRange(0, numConnected * 2);
        linesMesh.geometry.attributes.position.needsUpdate = true;

        // Update Theme colors dynamically depending on body attribute
        const currentTheme = document.documentElement.getAttribute('data-theme');
        if (currentTheme === 'dark') {
            pMaterial.color.setHex(0x4f8cff);
            lineMaterial.color.setHex(0x2addc4);
            lineMaterial.opacity = 0.2;
        } else {
            pMaterial.color.setHex(0x2b5ca8);
            lineMaterial.color.setHex(0x4f8cff);
            lineMaterial.opacity = 0.4;
        }

        renderer.render(scene, camera);
    }

    animate();

    // Window Resize Handler
    window.addEventListener('resize', () => {
        if (!container.clientWidth) return;
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });

    // Clean up observer if it unmounts (not strictly necessary here but good practice)
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Resume animation if out of view? Optional optimization.
            }
        });
    });
    observer.observe(container);
}

// Ensure ThreeJS starts if script loaded after Three.js
if (window.THREE) {
    initThreeJS();
} else {
    window.addEventListener('load', initThreeJS);
}
 *cascade08*cascade08 *cascade08*cascade08 *cascade08*cascade08 *cascade08*cascade08 *cascade08!*cascade08!" *cascade08"$*cascade08$' *cascade08')*cascade08)ò *cascade08òò*cascade08òŞ *cascade08ŞŞ*cascade08Ş–
 *cascade08–
¨
*cascade08¨
® *cascade08®µ*cascade08µ *cascade08¦*cascade08¦§ *cascade08§ª*cascade08ª« *cascade08«¯*cascade08¯´ *cascade08´¸*cascade08¸¹ *cascade08¹º*cascade08ºÄ *cascade08ÄÖ*cascade08ÖØ *cascade08Øé*cascade08éï *cascade08ïò*cascade08òó *cascade08óõ*cascade08õö *cascade08ö÷*cascade08÷ø *cascade08øù*cascade08ùü *cascade08ü€*cascade08€ *cascade08“*cascade08“” *cascade08”™*cascade08™› *cascade08›*cascade08 *cascade08Ÿ*cascade08Ÿ¥ *cascade08¥©*cascade08©Œ *cascade08Œ’*cascade08’“ *cascade08“ *cascade08 ¡ *cascade08¡ª*cascade08ª« *cascade08«°*cascade08°± *cascade08±¸*cascade08¸¹ *cascade08¹Ù*cascade08ÙÚ *cascade08Úİ*cascade08İŞ *cascade08Şé*cascade08éê *cascade08êò*cascade08òó *cascade08ó*cascade08Ÿ *cascade08Ÿ¨*cascade08¨© *cascade08©ª*cascade08ª« *cascade08«µ*cascade08µ· *cascade08·Ç*cascade08ÇÈ *cascade08ÈÕ*cascade08Õà *cascade08àâ*cascade08âå *cascade08åğ*cascade08ğñ *cascade08ñó*cascade08óô *cascade08ôŠ*cascade08Š‹ *cascade08‹Œ*cascade08Œ *cascade08*cascade08 *cascade08’*cascade08’“ *cascade08“›*cascade08›œ *cascade08œ£*cascade08£­ *cascade08­»*cascade08»¾ *cascade08¾À*cascade08ÀÁ *cascade08ÁĞ*cascade08ĞÑ *cascade08ÑÓ*cascade08ÓÔ *cascade08Ô×*cascade08×Ø *cascade08ØÚ*cascade08ÚÜ *cascade08Üá*cascade08áé *cascade08é©*cascade08©« *cascade08«®*cascade08®¯ *cascade08¯³*cascade08³´ *cascade08´µ*cascade08µ¶ *cascade08¶Û*cascade08Ûç *cascade08çê*cascade08êğ *cascade08ğü*cascade08üÿ *cascade08ÿŒ*cascade08Œ” *cascade08”•*cascade08•– *cascade08–¥*cascade08¥¦ *cascade08¦§*cascade08§© *cascade08©¬*cascade08¬± *cascade08±µ*cascade08µŒ *cascade08Œ¤*cascade08¤ª *cascade08ª¬*cascade08¬­ *cascade08­¯*cascade08¯° *cascade08°´*cascade08´µ *cascade08µ¸*cascade08¸¹ *cascade08¹»*cascade08»¼ *cascade08¼¾*cascade08¾¿ *cascade08¿À*cascade08ÀÃ *cascade08ÃÇ*cascade08ÇÈ *cascade08ÈÏ*cascade08Ï× *cascade08×Ş*cascade08Şà *cascade08àõ*cascade08õ÷ *cascade08÷ˆ*cascade08ˆ‰ *cascade08‰*cascade08• *cascade08•—*cascade08—˜ *cascade08˜›*cascade08› *cascade08¬*cascade08¬® *cascade08®¯*cascade08¯° *cascade08°µ*cascade08µ¶ *cascade08¶º*cascade08º¼ *cascade08¼Ç*cascade08ÇÈ *cascade08ÈÌ*cascade08ÌÒ *cascade08ÒÔ*cascade08ÔÕ *cascade08ÕÜ*cascade08Üİ *cascade08İá*cascade08áâ *cascade08âé*cascade08éê *cascade08êğ*cascade08ğñ *cascade08ñø*cascade08øı *cascade08ış*cascade08şÿ *cascade08ÿ… *cascade08… †  *cascade08† ‰ *cascade08‰ Š  *cascade08Š Œ *cascade08Œ   *cascade08  *cascade08 ˜  *cascade08˜  *cascade08   *cascade08 © *cascade08© ª  *cascade08ª « *cascade08« ¬  *cascade08¬ ³ *cascade08³ ´  *cascade08´ ¼ *cascade08¼ ¾  *cascade08¾ Ã *cascade08Ã Ä  *cascade08Ä Æ *cascade08Æ Ç  *cascade08Ç Í *cascade08Í Î  *cascade08Î Ğ *cascade08Ğ Ñ  *cascade08Ñ × *cascade08× Ù  *cascade08Ù Û *cascade08Û Ü  *cascade08Ü Ş *cascade08Ş è  *cascade08è ë *cascade08ë ì  *cascade08ì í *cascade08í î  *cascade08î ö *cascade08ö ÷  *cascade08÷ ü *cascade08ü ı  *cascade08ı ş *cascade08ş ÿ  *cascade08ÿ !*cascade08!‚! *cascade08‚!œ!*cascade08œ!¥! *cascade08¥!ª!*cascade08ª!³# *cascade08³#³#*cascade08³#Ä% *cascade08Ä%ø'*cascade08ø'š* *cascade08š*š**cascade08š*•; *cascade08•;•;*cascade08•;ñ< *cascade08ñ<ñ<*cascade08ñ<„E *cascade08„E„E*cascade08„EÉH *cascade08ÉHÉH*cascade08ÉH™I *cascade08™I™I*cascade08™I…L *cascade08…L†L*cascade08†L‡L *cascade08‡LˆL*cascade08ˆL»L *cascade08»L¼L*cascade08¼L½L *cascade08½L¾L*cascade08¾L¿L *cascade08¿LÀL*cascade08ÀLÁL *cascade08ÁLÂL*cascade08ÂLõL *cascade08õLöL*cascade08öL÷L *cascade08÷LøL*cascade08øLùL *cascade08ùLúL*cascade08úLûL *cascade08ûLüL*cascade08üLÕM *cascade08ÕMÖM*cascade08ÖM×M *cascade08×MØM*cascade08ØMûM *cascade08ûMüM*cascade08üMıM *cascade08ıMşM*cascade08şMN *cascade08NN*cascade08NŸN *cascade08ŸN N*cascade08 NäN *cascade08äNåN*cascade08åNæN *cascade08æNçN*cascade08çNèN *cascade08èNéN*cascade08éNêN *cascade08êNëN*cascade08ëNŠO *cascade08ŠO‹O*cascade08‹OŒO *cascade08ŒOO*cascade08OO *cascade08OO*cascade08OO *cascade08O‘O*cascade08‘OÕO *cascade08ÕOÖO*cascade08ÖO×O *cascade08×OØO*cascade08ØOÙO *cascade08ÙOÚO*cascade08ÚOÛO *cascade08ÛOÜO*cascade08ÜOûO *cascade08ûOüO*cascade08üOıO *cascade08ıOşO*cascade08şOÿO *cascade08ÿO€P*cascade08€PP *cascade08P‚P*cascade08‚PœR *cascade08œRR*cascade08RR *cascade08RŸR*cascade08ŸR³R *cascade08³R´R*cascade08´RµR *cascade08µR¶R*cascade08¶RåR *cascade08åRæR*cascade08æRçR *cascade08çRèR*cascade08èRéR *cascade08éRêR*cascade08êRëR *cascade08ëRìR*cascade08ìR€S *cascade08€SS*cascade08S‚S *cascade08‚SƒS*cascade08ƒS„S *cascade08„S…S*cascade08…S†S *cascade08†S‡S*cascade08‡S¶S *cascade08¶S·S*cascade08·S¸S *cascade08¸S¹S*cascade08¹SºS *cascade08ºS»S*cascade08»S¼S *cascade08¼S½S*cascade08½SÑS *cascade08ÑSÒS*cascade08ÒSÓS *cascade08ÓSÔS*cascade08ÔSÕS *cascade08ÕSÖS*cascade08ÖS×S *cascade08×SØS*cascade08ØS†T *cascade08†T‡T*cascade08‡TˆT *cascade08ˆT‰T*cascade08‰TT *cascade08T‘T*cascade08‘T’T *cascade08’T“T*cascade08“TšT *cascade08šT›T*cascade08›TœT *cascade08œTT*cascade08T´U *cascade08´UµU*cascade08µU¶U *cascade08¶U·U*cascade08·UıU *cascade08ıUşU*cascade08şUÿU *cascade08ÿU€V*cascade08€VV *cascade08V‚V*cascade08‚VƒV *cascade08ƒV„V*cascade08„VÊV *cascade08ÊVËV*cascade08ËVÌV *cascade08ÌVÍV*cascade08ÍVÎV *cascade08ÎVÏV*cascade08ÏVĞV *cascade08ĞVÑV*cascade08ÑV™W *cascade08™WšW*cascade08šW›W *cascade08›WœW*cascade08œWâW *cascade08âWãW*cascade08ãWäW *cascade08äWåW*cascade08åWæW *cascade08æWçW*cascade08çWèW *cascade08èWéW*cascade08éW¯X *cascade08¯X°X*cascade08°X±X *cascade08±X²X*cascade08²X³X *cascade08³X´X*cascade08´XµX *cascade08µX¶X*cascade08¶XÛb *cascade08ÛbÜb*cascade08Üb±e *cascade08"(a54ada5e9b5794c0afd61ea1b7f30b1bdacc946f2;file:///c:/Users/novtw/Documents/ghostnet-website/script.js: file:///c:/Users/novtw/Documents