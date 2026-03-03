öÂ// ============================================================
// BiogBrains ‚Äî Preschool Learning Platform
// Dynamic Content & 3D Components
// ============================================================

// ===== PRESCHOOL COURSE DATA =====
const coursesData = [
    {
        id: 1,
        title: "ABCs Adventure: Learn Letters with Animals! ü¶Å",
        desc: "Interactive letter recognition with cute animal friends. Phonics, tracing, and fun songs for every letter!",
        category: "toddler",
        categoryLabel: "Toddlers (2-3)",
        categoryColor: "#ff7e33",
        price: 29,
        originalPrice: 59,
        rating: 4.9,
        students: 8400,
        lessons: 32,
        badge: "bestseller",
        instructor: "Ms. Sarah",
        initials: "MS",
        gradient: 1,
        emoji: "üî§",
        avatarGradient: "linear-gradient(135deg, #ff7e33, #ff5593)"
    },
    {
        id: 2,
        title: "Counting & Numbers Fun 1-20 üî¢",
        desc: "Learn numbers through interactive games, counting songs, and hands-on activities with friendly characters.",
        category: "toddler",
        categoryLabel: "Toddlers (2-3)",
        categoryColor: "#9b5de5",
        price: 29,
        originalPrice: 59,
        rating: 4.8,
        students: 7200,
        lessons: 28,
        badge: "bestseller",
        instructor: "Mr. James",
        initials: "MJ",
        gradient: 2,
        emoji: "üßÆ",
        avatarGradient: "linear-gradient(135deg, #9b5de5, #00d4ff)"
    },
    {
        id: 3,
        title: "Little Artists: Colors, Shapes & Creativity üé®",
        desc: "Unleash creativity! Drawing, painting, crafts, and color exploration in a magical art studio.",
        category: "preschool",
        categoryLabel: "Preschool (3-5)",
        categoryColor: "#ffe44d",
        price: 34,
        originalPrice: 69,
        rating: 4.9,
        students: 6100,
        lessons: 36,
        badge: "new",
        instructor: "Ms. Maya",
        initials: "MM",
        gradient: 3,
        emoji: "üñçÔ∏è",
        avatarGradient: "linear-gradient(135deg, #ffe44d, #ff7e33)"
    },
    {
        id: 4,
        title: "Dinosaur Discovery: Science for Kids ü¶ï",
        desc: "Travel back in time! Learn about dinosaurs, fossils, volcanoes, and the prehistoric world.",
        category: "preschool",
        categoryLabel: "Preschool (3-5)",
        categoryColor: "#00e676",
        price: 39,
        originalPrice: 79,
        rating: 4.9,
        students: 5800,
        lessons: 24,
        badge: "new",
        instructor: "Dr. Alex",
        initials: "DA",
        gradient: 4,
        emoji: "ü¶ñ",
        avatarGradient: "linear-gradient(135deg, #00e676, #00d4ff)"
    },
    {
        id: 5,
        title: "Music & Movement: Sing, Dance, Play! üéµ",
        desc: "Musical instruments, rhythm games, dance moves, and sing-along's that build coordination and joy!",
        category: "toddler",
        categoryLabel: "Toddlers (2-3)",
        categoryColor: "#ff5593",
        price: 24,
        originalPrice: 49,
        rating: 4.7,
        students: 4600,
        lessons: 20,
        badge: null,
        instructor: "Ms. Emma",
        initials: "ME",
        gradient: 5,
        emoji: "ü•Å",
        avatarGradient: "linear-gradient(135deg, #ff5593, #9b5de5)"
    },
    {
        id: 6,
        title: "Reading Ready: Phonics & First Words üìñ",
        desc: "Build strong reading foundations with phonics games, sight words, and interactive storybooks.",
        category: "kindergarten",
        categoryLabel: "Kindergarten (5-6)",
        categoryColor: "#4da6ff",
        price: 39,
        originalPrice: 79,
        rating: 4.8,
        students: 7400,
        lessons: 40,
        badge: "bestseller",
        instructor: "Ms. Chen",
        initials: "MC",
        gradient: 6,
        emoji: "üìö",
        avatarGradient: "linear-gradient(135deg, #4da6ff, #9b5de5)"
    },
    {
        id: 7,
        title: "Space Explorers: Journey to the Stars üöÄ",
        desc: "Blast off! Learn about planets, stars, astronauts, and the amazing universe in this cosmic adventure.",
        category: "preschool",
        categoryLabel: "Preschool (3-5)",
        categoryColor: "#00d4ff",
        price: 34,
        originalPrice: 69,
        rating: 4.8,
        students: 5100,
        lessons: 22,
        badge: null,
        instructor: "Mr. Neil",
        initials: "MN",
        gradient: 8,
        emoji: "ü™ê",
        avatarGradient: "linear-gradient(135deg, #00d4ff, #9b5de5)"
    },
    {
        id: 8,
        title: "Math Superstars: Addition & Patterns üåü",
        desc: "Fun math adventures with addition, subtraction, patterns, and problem-solving games for big kids!",
        category: "kindergarten",
        categoryLabel: "Kindergarten (5-6)",
        categoryColor: "#ff7e33",
        price: 39,
        originalPrice: 79,
        rating: 4.7,
        students: 4300,
        lessons: 35,
        badge: null,
        instructor: "Mr. Park",
        initials: "MP",
        gradient: 7,
        emoji: "‚ûï",
        avatarGradient: "linear-gradient(135deg, #ff7e33, #ffe44d)"
    }
];

// ===== PRICING DATA =====
const pricingData = {
    monthly: [
        {
            name: "Free Explorer üÜì",
            desc: "Try it out ‚Äî no credit card needed",
            price: 0,
            period: "/mo",
            features: [
                "3 free starter courses",
                "Limited interactive activities",
                "Basic progress tracking",
                "1 child profile",
                "Community access"
            ],
            btnText: "Start Free",
            btnClass: "btn-ghost"
        },
        {
            name: "Family Plan ‚≠ê",
            desc: "Most popular for families",
            price: 14,
            period: "/mo",
            featured: true,
            features: [
                "All 150+ courses unlocked",
                "Unlimited interactive games",
                "Detailed progress reports",
                "Up to 3 child profiles",
                "Offline downloads",
                "Printable worksheets",
                "Parent educator tips",
                "Priority support"
            ],
            btnText: "Start 7-Day Free Trial",
            btnClass: "btn-primary"
        },
        {
            name: "School / Group üè´",
            desc: "For classrooms and daycare",
            price: 49,
            period: "/mo",
            features: [
                "Everything in Family Plan",
                "Up to 30 child profiles",
                "Teacher dashboard",
                "Classroom activity plans",
                "Analytics & reporting",
                "Custom learning paths",
                "Training for educators",
                "Dedicated support manager"
            ],
            btnText: "Contact Us",
            btnClass: "btn-ghost"
        }
    ],
    yearly: [
        {
            name: "Free Explorer üÜì",
            desc: "Try it out ‚Äî no credit card needed",
            price: 0,
            period: "/yr",
            features: [
                "3 free starter courses",
                "Limited interactive activities",
                "Basic progress tracking",
                "1 child profile",
                "Community access"
            ],
            btnText: "Start Free",
            btnClass: "btn-ghost"
        },
        {
            name: "Family Plan ‚≠ê",
            desc: "Most popular for families",
            price: 99,
            period: "/yr",
            featured: true,
            features: [
                "All 150+ courses unlocked",
                "Unlimited interactive games",
                "Detailed progress reports",
                "Up to 3 child profiles",
                "Offline downloads",
                "Printable worksheets",
                "Parent educator tips",
                "Priority support"
            ],
            btnText: "Start 7-Day Free Trial",
            btnClass: "btn-primary"
        },
        {
            name: "School / Group üè´",
            desc: "For classrooms and daycare",
            price: 299,
            period: "/yr",
            features: [
                "Everything in Family Plan",
                "Up to 30 child profiles",
                "Teacher dashboard",
                "Classroom activity plans",
                "Analytics & reporting",
                "Custom learning paths",
                "Training for educators",
                "Dedicated support manager"
            ],
            btnText: "Contact Us",
            btnClass: "btn-ghost"
        }
    ]
};

// ===== TESTIMONIALS DATA =====
const testimonialsData = [
    {
        text: "My 3-year-old LOVES BiogBrains! She learned all her letters in just 3 weeks and now 'reads' to her stuffed animals every night. The animations are so engaging!",
        name: "Jessica M.",
        role: "Mom of Lily, age 3",
        rating: 5,
        avatar: "üë©",
        gradient: "linear-gradient(135deg, #ff7e33, #ff5593)"
    },
    {
        text: "As a preschool teacher, this is the best educational platform I've seen. The curriculum is developmentally appropriate, and my students are always excited for 'BiogBrains time'!",
        name: "Ms. Thompson",
        role: "Preschool Teacher, 12 yrs exp.",
        rating: 5,
        avatar: "üë©‚Äçüè´",
        gradient: "linear-gradient(135deg, #9b5de5, #00d4ff)"
    },
    {
        text: "Worth every penny! Two of my kids use it daily. The dinosaur course alone has taught my son more science than I thought a 4-year-old could learn. Amazing!",
        name: "David K.",
        role: "Father of twins, age 4",
        rating: 5,
        avatar: "üë®",
        gradient: "linear-gradient(135deg, #00e676, #00d4ff)"
    },
    {
        text: "The progress reports are incredible ‚Äî I can see exactly what my daughter is learning. The activities are safe, ad-free, and she doesn't want to stop learning!",
        name: "Maria S.",
        role: "Mom of Sofia, age 5",
        rating: 5,
        avatar: "üë©",
        gradient: "linear-gradient(135deg, #ffe44d, #ff7e33)"
    },
    {
        text: "We implement BiogBrains across our entire daycare network. The school dashboard and classroom plans save our teachers hours of prep time. Kids genuinely love it.",
        name: "Robert Chen",
        role: "Director, BrightStart Daycare",
        rating: 5,
        avatar: "üë®‚Äçüíº",
        gradient: "linear-gradient(135deg, #ff5593, #9b5de5)"
    },
    {
        text: "My shy little boy has come out of his shell through the social skills course. He now introduces himself to other kids on the playground. I'm so grateful!",
        name: "Amanda W.",
        role: "Mom of Ethan, age 3",
        rating: 5,
        avatar: "üë©",
        gradient: "linear-gradient(135deg, #4da6ff, #00d4ff)"
    }
];


// ============================================================
// THREE.JS 3D COMPONENTS ‚Äî Playful & Child-Friendly
// ============================================================

// ===== 1. HERO BACKGROUND ‚Äî Colorful Star Particles =====
function initHeroBackground() {
    const canvas = document.getElementById('hero-canvas');
    if (!canvas) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Colorful star particles
    const particleCount = 600;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);
    const sizes = new Float32Array(particleCount);

    const colorPalette = [
        [1.0, 0.49, 0.2],   // orange
        [1.0, 0.33, 0.58],  // pink
        [0.61, 0.36, 0.9],  // purple
        [0.0, 0.83, 1.0],   // cyan
        [0.0, 0.9, 0.46],   // green
        [1.0, 0.89, 0.3],   // yellow
    ];

    for (let i = 0; i < particleCount; i++) {
        positions[i * 3] = (Math.random() - 0.5) * 50;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 50;
        positions[i * 3 + 2] = (Math.random() - 0.5) * 50;

        const color = colorPalette[Math.floor(Math.random() * colorPalette.length)];
        colors[i * 3] = color[0];
        colors[i * 3 + 1] = color[1];
        colors[i * 3 + 2] = color[2];

        sizes[i] = Math.random() * 0.08 + 0.03;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 0.07,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        sizeAttenuation: true
    });

    const particles = new THREE.Points(geometry, material);
    scene.add(particles);

    camera.position.z = 20;

    let mouseX = 0, mouseY = 0;
    document.addEventListener('mousemove', (e) => {
        mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
        mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    });

    function animate() {
        requestAnimationFrame(animate);
        particles.rotation.y += 0.0004;
        particles.rotation.x += 0.0002;

        // Mouse parallax
        camera.position.x += (mouseX * 3 - camera.position.x) * 0.015;
        camera.position.y += (-mouseY * 3 - camera.position.y) * 0.015;

        renderer.render(scene, camera);
    }

    animate();

    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// ===== 2. HERO 3D ‚Äî Playful Globe with Orbiting Elements =====
function initHero3D() {
    const container = document.getElementById('hero-3d');
    const canvas = document.getElementById('course-3d-canvas');
    if (!canvas || !container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, container.clientWidth / container.clientHeight, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.5);
    scene.add(ambientLight);

    const pointLight1 = new THREE.PointLight(0xff7e33, 2.5, 50);
    pointLight1.position.set(5, 5, 5);
    scene.add(pointLight1);

    const pointLight2 = new THREE.PointLight(0x00d4ff, 2, 50);
    pointLight2.position.set(-5, -3, 3);
    scene.add(pointLight2);

    const pointLight3 = new THREE.PointLight(0xff5593, 2, 50);
    pointLight3.position.set(0, 5, -5);
    scene.add(pointLight3);

    // Central sphere ‚Äî "learning globe"
    const sphereGeo = new THREE.SphereGeometry(2, 32, 32);
    const sphereMat = new THREE.MeshPhongMaterial({
        color: 0x9b5de5,
        emissive: 0x2a0a5e,
        specular: 0xffffff,
        shininess: 80,
        transparent: true,
        opacity: 0.75
    });
    const sphere = new THREE.Mesh(sphereGeo, sphereMat);
    scene.add(sphere);

    // Wireframe overlay
    const wireGeo = new THREE.IcosahedronGeometry(2.15, 1);
    const wireMat = new THREE.MeshBasicMaterial({
        color: 0xff7e33,
        wireframe: true,
        transparent: true,
        opacity: 0.2
    });
    const wireframe = new THREE.Mesh(wireGeo, wireMat);
    scene.add(wireframe);

    // Orbiting rings ‚Äî colorful
    const ringColors = [0xff7e33, 0x00d4ff, 0xff5593];
    const ringTilts = [Math.PI / 3, -Math.PI / 4, Math.PI / 1.8];
    const ringSizes = [3.2, 3.6, 4.0];
    const rings = [];

    for (let i = 0; i < 3; i++) {
        const ringGeo = new THREE.TorusGeometry(ringSizes[i], 0.035 - i * 0.005, 16, 100);
        const ringMat = new THREE.MeshBasicMaterial({
            color: ringColors[i],
            transparent: true,
            opacity: 0.35 - i * 0.08
        });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.rotation.x = ringTilts[i];
        if (i > 0) ring.rotation.y = Math.PI / (3 + i);
        scene.add(ring);
        rings.push(ring);
    }

    // Orbiting "course" shapes ‚Äî playful geometries
    const orbiters = [];
    const shapes = [
        { geo: new THREE.TetrahedronGeometry(0.2), color: 0xff7e33 },
        { geo: new THREE.OctahedronGeometry(0.18), color: 0xff5593 },
        { geo: new THREE.BoxGeometry(0.22, 0.22, 0.22), color: 0x00d4ff },
        { geo: new THREE.DodecahedronGeometry(0.16), color: 0x00e676 },
        { geo: new THREE.IcosahedronGeometry(0.18), color: 0xffe44d },
        { geo: new THREE.SphereGeometry(0.14, 8, 8), color: 0x9b5de5 },
        { geo: new THREE.ConeGeometry(0.12, 0.25, 6), color: 0x4da6ff },
    ];

    for (let i = 0; i < shapes.length; i++) {
        const mat = new THREE.MeshPhongMaterial({
            color: shapes[i].color,
            emissive: shapes[i].color,
            emissiveIntensity: 0.3,
            flatShading: true
        });
        const mesh = new THREE.Mesh(shapes[i].geo, mat);
        mesh.userData = {
            radius: 3 + i * 0.4,
            speed: 0.25 + i * 0.1,
            offset: (Math.PI * 2 / shapes.length) * i,
            yOffset: (Math.random() - 0.5) * 2.5,
            rotSpeed: 0.02 + Math.random() * 0.03
        };
        scene.add(mesh);
        orbiters.push(mesh);
    }

    camera.position.z = 8;
    camera.position.y = 0.5;

    let mouseX = 0, mouseY = 0;
    container.addEventListener('mousemove', (e) => {
        const rect = container.getBoundingClientRect();
        mouseX = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
        mouseY = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
    });

    function animate() {
        requestAnimationFrame(animate);
        const time = Date.now() * 0.001;

        sphere.rotation.y += 0.004;
        sphere.rotation.x += 0.001;
        wireframe.rotation.y += 0.005;
        wireframe.rotation.x = sphere.rotation.x;

        // Float
        sphere.position.y = Math.sin(time * 0.6) * 0.25;
        wireframe.position.y = sphere.position.y;

        // Rings
        rings.forEach((ring, i) => {
            ring.rotation.z += 0.002 * (i + 1);
            ring.rotation.y += 0.001 * (i + 1);
        });

        // Orbiting shapes
        orbiters.forEach(orbiter => {
            const d = orbiter.userData;
            orbiter.position.x = Math.cos(time * d.speed + d.offset) * d.radius;
            orbiter.position.z = Math.sin(time * d.speed + d.offset) * d.radius;
            orbiter.position.y = Math.sin(time * d.speed * 0.7 + d.offset) * d.yOffset;
            orbiter.rotation.x += d.rotSpeed;
            orbiter.rotation.y += d.rotSpeed * 0.8;
        });

        // Mouse interaction
        scene.rotation.y += (mouseX * 0.3 - scene.rotation.y) * 0.04;
        scene.rotation.x += (-mouseY * 0.2 - scene.rotation.x) * 0.04;

        renderer.render(scene, camera);
    }

    animate();

    const resizeObserver = new ResizeObserver(() => {
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });
    resizeObserver.observe(container);
}

// ===== 3. SHOWCASE 3D ‚Äî Magical Learning World =====
function initShowcase3D() {
    const container = document.getElementById('showcase-3d-container');
    const canvas = document.getElementById('showcase-canvas');
    if (!canvas || !container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, container.clientWidth / container.clientHeight, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 2);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0xff7e33, 1.5);
    dirLight.position.set(5, 5, 5);
    scene.add(dirLight);

    const pointLight = new THREE.PointLight(0x00d4ff, 2, 30);
    pointLight.position.set(-3, 2, 4);
    scene.add(pointLight);

    const group = new THREE.Group();

    // Central ‚Äî large star shape (icosahedron)
    const starGeo = new THREE.IcosahedronGeometry(1.8, 0);
    const starMat = new THREE.MeshPhongMaterial({
        color: 0xffe44d,
        emissive: 0x5a4a00,
        specular: 0xffffff,
        shininess: 100,
        flatShading: true,
        transparent: true,
        opacity: 0.8
    });
    const star = new THREE.Mesh(starGeo, starMat);
    group.add(star);

    // Wireframe
    const starWireGeo = new THREE.IcosahedronGeometry(1.9, 0);
    const starWireMat = new THREE.MeshBasicMaterial({
        color: 0xff7e33,
        wireframe: true,
        transparent: true,
        opacity: 0.15
    });
    const starWire = new THREE.Mesh(starWireGeo, starWireMat);
    group.add(starWire);

    // Floating learning objects
    const floatingShapes = [];
    const shapeConfigs = [
        { geo: new THREE.BoxGeometry(0.3, 0.3, 0.3), color: 0xff7e33 },      // Block
        { geo: new THREE.SphereGeometry(0.18, 16, 16), color: 0xff5593 },     // Ball
        { geo: new THREE.ConeGeometry(0.15, 0.35, 6), color: 0x00e676 },      // Tree
        { geo: new THREE.TetrahedronGeometry(0.2), color: 0x00d4ff },          // Crystal
        { geo: new THREE.TorusGeometry(0.15, 0.06, 8, 16), color: 0x9b5de5 }, // Ring
        { geo: new THREE.OctahedronGeometry(0.18), color: 0xffe44d },          // Star
        { geo: new THREE.DodecahedronGeometry(0.16), color: 0x4da6ff },        // Gem
        { geo: new THREE.CylinderGeometry(0.1, 0.1, 0.3, 8), color: 0xff7e33 }, // Pencil
        { geo: new THREE.BoxGeometry(0.25, 0.15, 0.02), color: 0x00e676 },    // Board
        { geo: new THREE.SphereGeometry(0.12, 6, 6), color: 0xff5593 },       // Bubble
        { geo: new THREE.TetrahedronGeometry(0.15), color: 0x9b5de5 },
        { geo: new THREE.OctahedronGeometry(0.14), color: 0xffe44d },
        { geo: new THREE.ConeGeometry(0.1, 0.2, 5), color: 0x00d4ff },
        { geo: new THREE.BoxGeometry(0.18, 0.18, 0.18), color: 0xff7e33 },
        { geo: new THREE.SphereGeometry(0.1, 8, 8), color: 0x4da6ff },
    ];

    for (let i = 0; i < shapeConfigs.length; i++) {
        const mat = new THREE.MeshPhongMaterial({
            color: shapeConfigs[i].color,
            emissive: shapeConfigs[i].color,
            emissiveIntensity: 0.2,
            flatShading: true,
            transparent: true,
            opacity: 0.8
        });
        const mesh = new THREE.Mesh(shapeConfigs[i].geo, mat);
        mesh.userData = {
            angle: (Math.PI * 2 / shapeConfigs.length) * i,
            radius: 2.5 + Math.random() * 2,
            speed: 0.15 + Math.random() * 0.25,
            yAmplitude: 0.5 + Math.random() * 1.5,
            rotSpeed: 0.01 + Math.random() * 0.04
        };
        group.add(mesh);
        floatingShapes.push(mesh);
    }

    // Sparkle particles
    const sparkleCount = 150;
    const sparkleGeo = new THREE.BufferGeometry();
    const sparklePos = new Float32Array(sparkleCount * 3);
    const sparkleColors = new Float32Array(sparkleCount * 3);

    const sparkPalette = [
        [1.0, 0.89, 0.3],
        [1.0, 0.49, 0.2],
        [1.0, 0.33, 0.58],
        [0.0, 0.83, 1.0],
    ];

    for (let i = 0; i < sparkleCount; i++) {
        const angle = Math.random() * Math.PI * 2;
        const radius = 2 + Math.random() * 3;
        sparklePos[i * 3] = Math.cos(angle) * radius;
        sparklePos[i * 3 + 1] = (Math.random() - 0.5) * 4;
        sparklePos[i * 3 + 2] = Math.sin(angle) * radius;

        const c = sparkPalette[Math.floor(Math.random() * sparkPalette.length)];
        sparkleColors[i * 3] = c[0];
        sparkleColors[i * 3 + 1] = c[1];
        sparkleColors[i * 3 + 2] = c[2];
    }

    sparkleGeo.setAttribute('position', new THREE.BufferAttribute(sparklePos, 3));
    sparkleGeo.setAttribute('color', new THREE.BufferAttribute(sparkleColors, 3));

    const sparkleMat = new THREE.PointsMaterial({
        size: 0.06,
        vertexColors: true,
        transparent: true,
        opacity: 0.7
    });
    const sparkles = new THREE.Points(sparkleGeo, sparkleMat);
    group.add(sparkles);

    scene.add(group);
    camera.position.z = 7;
    camera.position.y = 0.5;

    let mouseX = 0, mouseY = 0;
    container.addEventListener('mousemove', (e) => {
        const rect = container.getBoundingClientRect();
        mouseX = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
        mouseY = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
    });

    function animate() {
        requestAnimationFrame(animate);
        const time = Date.now() * 0.001;

        star.rotation.y += 0.005;
        star.rotation.x += 0.003;
        starWire.rotation.y = star.rotation.y;
        starWire.rotation.x = star.rotation.x;

        star.position.y = Math.sin(time * 0.5) * 0.2;
        starWire.position.y = star.position.y;

        floatingShapes.forEach(shape => {
            const d = shape.userData;
            shape.position.x = Math.cos(time * d.speed + d.angle) * d.radius;
            shape.position.z = Math.sin(time * d.speed + d.angle) * d.radius;
            shape.position.y = Math.sin(time * d.speed * 1.3 + d.angle) * d.yAmplitude;
            shape.rotation.x += d.rotSpeed;
            shape.rotation.y += d.rotSpeed * 0.7;
        });

        sparkles.rotation.y += 0.003;

        group.rotation.y += (mouseX * 0.4 - group.rotation.y) * 0.03;
        group.rotation.x += (-mouseY * 0.25 - group.rotation.x) * 0.03;

        renderer.render(scene, camera);
    }

    animate();

    const resizeObserver = new ResizeObserver(() => {
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });
    resizeObserver.observe(container);
}

// ===== 4. FEATURE 3D ‚Äî Fun Spinning ABC Block =====
function initFeature3D() {
    const container = document.getElementById('feature-3d-demo');
    if (!container) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, container.clientWidth / container.clientHeight, 0.1, 100);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const ambientLight = new THREE.AmbientLight(0xffffff, 2);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0xff7e33, 3, 20);
    pointLight.position.set(3, 3, 3);
    scene.add(pointLight);

    const pointLight2 = new THREE.PointLight(0x00d4ff, 2, 20);
    pointLight2.position.set(-3, -2, 3);
    scene.add(pointLight2);

    // ABC blocks ‚Äî 3 colored cubes
    const blockGroup = new THREE.Group();

    const blockColors = [0xff7e33, 0x9b5de5, 0x00e676];
    const blockPositions = [[-0.8, 0, 0], [0, 0.6, 0.3], [0.8, 0, 0]];

    for (let i = 0; i < 3; i++) {
        const cubeGeo = new THREE.BoxGeometry(0.65, 0.65, 0.65);

        // Create edges for a toy-block look
        const cubeMat = new THREE.MeshPhongMaterial({
            color: blockColors[i],
            emissive: blockColors[i],
            emissiveIntensity: 0.15,
            specular: 0xffffff,
            shininess: 60
        });
        const cube = new THREE.Mesh(cubeGeo, cubeMat);
        cube.position.set(...blockPositions[i]);
        cube.rotation.y = Math.PI / 6 * (i + 1);
        cube.rotation.z = Math.PI / 12 * i;
        blockGroup.add(cube);

        // Edges
        const edgesGeo = new THREE.EdgesGeometry(cubeGeo);
        const edgesMat = new THREE.LineBasicMaterial({ color: 0xffffff, opacity: 0.3, transparent: true });
        const edges = new THREE.LineSegments(edgesGeo, edgesMat);
        edges.position.copy(cube.position);
        edges.rotation.copy(cube.rotation);
        blockGroup.add(edges);
    }

    // Orbiting small stars
    for (let i = 0; i < 8; i++) {
        const starGeo = new THREE.TetrahedronGeometry(0.06);
        const starMat = new THREE.MeshPhongMaterial({
            color: 0xffe44d,
            emissive: 0xffe44d,
            emissiveIntensity: 0.5
        });
        const star = new THREE.Mesh(starGeo, starMat);
        star.userData = {
            angle: (Math.PI * 2 / 8) * i,
            radius: 1.2 + Math.random() * 0.3,
            speed: 0.5 + Math.random() * 0.5,
            yAmp: 0.2 + Math.random() * 0.3
        };
        blockGroup.add(star);
    }

    scene.add(blockGroup);
    camera.position.z = 3;

    function animate() {
        requestAnimationFrame(animate);
        const time = Date.now() * 0.001;

        blockGroup.rotation.y += 0.006;
        blockGroup.position.y = Math.sin(time * 0.8) * 0.1;

        // Rotate individual blocks
        blockGroup.children.forEach((child, i) => {
            if (child.isMesh && child.geometry.type === 'BoxGeometry') {
                child.rotation.x += 0.003;
                child.rotation.z += 0.002;
            }
            // Orbiting stars
            if (child.userData && child.userData.angle !== undefined) {
                const d = child.userData;
                child.position.x = Math.cos(time * d.speed + d.angle) * d.radius;
                child.position.z = Math.sin(time * d.speed + d.angle) * d.radius;
                child.position.y = Math.sin(time * d.speed * 1.5 + d.angle) * d.yAmp;
                child.rotation.x += 0.03;
                child.rotation.y += 0.03;
            }
        });

        renderer.render(scene, camera);
    }

    animate();

    const resizeObserver = new ResizeObserver(() => {
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });
    resizeObserver.observe(container);
}


// ============================================================
// DYNAMIC UI COMPONENTS
// ============================================================

// ===== RENDER COURSES =====
function renderCourses(filter = 'all') {
    const grid = document.getElementById('course-grid');
    if (!grid) return;

    const filtered = filter === 'all'
        ? coursesData
        : coursesData.filter(c => c.category === filter);

    grid.innerHTML = filtered.map((course, index) => `
        <div class="course-card reveal" style="animation-delay: ${index * 0.1}s" data-category="${course.category}">
            <div class="course-card-image">
                <div class="course-gradient course-gradient-${course.gradient}">${course.emoji}</div>
                ${course.badge ? `<span class="course-badge ${course.badge}">${course.badge === 'bestseller' ? 'üî• Bestseller' : '‚ú® New'}</span>` : ''}
            </div>
            <div class="course-card-body">
                <div class="course-category" style="color: ${course.categoryColor}">${course.categoryLabel}</div>
                <h3 class="course-title">${course.title}</h3>
                <p class="course-desc">${course.desc}</p>
                <div class="course-meta">
                    <span class="course-meta-item course-rating">‚òÖ ${course.rating}</span>
                    <span class="course-meta-item">üë∂ ${(course.students / 1000).toFixed(1)}k kids</span>
                    <span class="course-meta-item">üìñ ${course.lessons} lessons</span>
                </div>
                <div class="course-footer">
                    <div class="course-instructor">
                        <div class="instructor-avatar" style="background: ${course.avatarGradient}">${course.initials}</div>
                        <span class="instructor-name">${course.instructor}</span>
                    </div>
                    <div class="course-price">
                        $${course.price}<span class="original-price">$${course.originalPrice}</span>
                    </div>
                </div>
            </div>
        </div>
    `).join('');

    // Re-trigger scroll reveal
    setTimeout(() => {
        document.querySelectorAll('.course-card.reveal').forEach(el => {
            el.classList.add('visible');
        });
    }, 100);
}

// ===== RENDER PRICING =====
function renderPricing(period = 'monthly') {
    const grid = document.getElementById('pricing-grid');
    if (!grid) return;

    const plans = pricingData[period];

    grid.innerHTML = plans.map(plan => `
        <div class="pricing-card ${plan.featured ? 'featured' : ''}">
            ${plan.featured ? '<div class="pricing-popular-badge">Most Popular</div>' : ''}
            <h3 class="pricing-plan-name">${plan.name}</h3>
            <p class="pricing-plan-desc">${plan.desc}</p>
            <div class="pricing-amount">
                <span class="pricing-currency">$</span>
                <span class="pricing-value">${plan.price}</span>
                <span class="pricing-period">${plan.period}</span>
            </div>
            <ul class="pricing-features">
                ${plan.features.map(f => `
                    <li>
                        <span class="pricing-check">‚úì</span>
                        ${f}
                    </li>
                `).join('')}
            </ul>
            <button class="btn ${plan.btnClass} btn-large">${plan.btnText}</button>
        </div>
    `).join('');
}

// ===== RENDER TESTIMONIALS =====
let currentTestimonialPage = 0;

function renderTestimonials() {
    const carousel = document.getElementById('testimonials-carousel');
    const dotsContainer = document.getElementById('carousel-dots');
    if (!carousel || !dotsContainer) return;

    carousel.innerHTML = testimonialsData.map(t => `
        <div class="testimonial-card">
            <div class="testimonial-stars">${'‚òÖ'.repeat(t.rating)}</div>
            <p class="testimonial-text">"${t.text}"</p>
            <div class="testimonial-author">
                <div class="testimonial-avatar" style="background: ${t.gradient}; font-size: 24px;">${t.avatar}</div>
                <div class="testimonial-info">
                    <h4>${t.name}</h4>
                    <p>${t.role}</p>
                </div>
            </div>
        </div>
    `).join('');

    const totalPages = Math.ceil(testimonialsData.length / getTestimonialsPerPage());
    dotsContainer.innerHTML = '';
    for (let i = 0; i < totalPages; i++) {
        const dot = document.createElement('div');
        dot.className = `carousel-dot ${i === 0 ? 'active' : ''}`;
        dot.addEventListener('click', () => goToTestimonialPage(i));
        dotsContainer.appendChild(dot);
    }
}

function getTestimonialsPerPage() {
    if (window.innerWidth < 768) return 1;
    if (window.innerWidth < 1024) return 2;
    return 3;
}

function goToTestimonialPage(page) {
    const carousel = document.getElementById('testimonials-carousel');
    const dots = document.querySelectorAll('.carousel-dot');
    const perPage = getTestimonialsPerPage();
    const totalPages = Math.ceil(testimonialsData.length / perPage);

    currentTestimonialPage = Math.max(0, Math.min(page, totalPages - 1));

    const cardWidth = carousel.querySelector('.testimonial-card')?.offsetWidth || 0;
    const gap = 24;
    const offset = currentTestimonialPage * (cardWidth + gap) * perPage;
    carousel.style.transform = `translateX(-${offset}px)`;
    carousel.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';

    dots.forEach((dot, i) => {
        dot.classList.toggle('active', i === currentTestimonialPage);
    });
}


// ============================================================
// EVENT HANDLERS & INTERACTIVITY
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

    // ===== NAVBAR SCROLL =====
    const navbar = document.getElementById('navbar');
    window.addEventListener('scroll', () => {
        navbar.classList.toggle('scrolled', window.scrollY > 50);
    });

    // ===== ANIMATED COUNTERS =====
    function animateCountUp() {
        const counters = document.querySelectorAll('.stat-number');
        counters.forEach(counter => {
            const target = parseInt(counter.getAttribute('data-target'));
            const duration = 2000;
            const start = performance.now();

            function update(now) {
                const elapsed = now - start;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                counter.textContent = Math.floor(target * eased).toLocaleString();
                if (progress < 1) requestAnimationFrame(update);
            }

            requestAnimationFrame(update);
        });
    }

    const statsObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCountUp();
                statsObserver.disconnect();
            }
        });
    }, { threshold: 0.5 });

    const heroStats = document.querySelector('.hero-stats');
    if (heroStats) statsObserver.observe(heroStats);

    // ===== COURSE FILTERS =====
    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderCourses(btn.dataset.filter);
        });
    });

    // ===== PRICING TOGGLE =====
    const toggleSwitch = document.getElementById('toggle-switch');
    const toggleLabels = document.querySelectorAll('.toggle-label');
    let isYearly = false;

    if (toggleSwitch) {
        toggleSwitch.addEventListener('click', () => {
            isYearly = !isYearly;
            toggleSwitch.classList.toggle('active', isYearly);
            toggleLabels.forEach(label => {
                label.classList.toggle('active', label.dataset.period === (isYearly ? 'yearly' : 'monthly'));
            });
            renderPricing(isYearly ? 'yearly' : 'monthly');
        });
    }

    // ===== TESTIMONIALS NAVIGATION =====
    document.getElementById('prev-testimonial')?.addEventListener('click', () => {
        goToTestimonialPage(currentTestimonialPage - 1);
    });

    document.getElementById('next-testimonial')?.addEventListener('click', () => {
        goToTestimonialPage(currentTestimonialPage + 1);
    });

    // ===== MODAL =====
    const modalOverlay = document.getElementById('modal-overlay');
    const modalCloseBtn = document.getElementById('modal-close');

    function openModal() {
        modalOverlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closeModal() {
        modalOverlay.classList.remove('active');
        document.body.style.overflow = '';
    }

    document.getElementById('btn-signup')?.addEventListener('click', openModal);
    document.getElementById('btn-cta-start')?.addEventListener('click', openModal);
    modalCloseBtn?.addEventListener('click', closeModal);
    modalOverlay?.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });

    // ===== SMOOTH SCROLL =====
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) target.scrollIntoView({ behavior: 'smooth' });
        });
    });

    // ===== SCROLL REVEAL =====
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

    function observeRevealElements() {
        document.querySelectorAll('.reveal, .feature-card, .pricing-card, .testimonial-card').forEach(el => {
            el.classList.add('reveal');
            revealObserver.observe(el);
        });
    }

    // ===== SIGNUP FORM =====
    document.getElementById('signup-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const name = document.getElementById('signup-name').value;
        const child = document.getElementById('signup-child').value;

        const modal = document.getElementById('signup-modal');
        modal.innerHTML = `
            <div style="text-align: center; padding: 40px 0;">
                <div style="font-size: 64px; margin-bottom: 16px;">üéâüßíüåü</div>
                <h2 style="font-family: var(--font-display); margin-bottom: 8px;">Welcome to BiogBrains!</h2>
                <p style="color: var(--text-secondary); margin-bottom: 8px;">Hi ${name}! ${child}'s learning adventure starts now!</p>
                <p style="color: var(--text-tertiary); font-size: 14px; margin-bottom: 24px;">Check your email for login details and get ready for some fun! üöÄ</p>
                <button class="btn btn-primary btn-large" onclick="document.getElementById('modal-overlay').classList.remove('active'); document.body.style.overflow = '';">Let's Go! üéÆ</button>
            </div>
        `;
    });

    // ===== MOBILE MENU =====
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const navLinks = document.getElementById('nav-links');
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            mobileMenuBtn.classList.toggle('active');
        });
    }

    // ===== COURSE CARD 3D TILT =====
    document.addEventListener('mousemove', (e) => {
        document.querySelectorAll('.course-card').forEach(card => {
            const rect = card.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
            const y = ((e.clientY - rect.top) / rect.height - 0.5) * 2;

            if (Math.abs(x) <= 1 && Math.abs(y) <= 1) {
                card.style.transform = `perspective(1000px) rotateY(${x * 6}deg) rotateX(${-y * 6}deg) translateY(-10px) scale(1.01)`;
            } else {
                card.style.transform = '';
            }
        });
    });

    // ===== CHARACTER SCROLL ‚Äî duplicate for infinite scroll =====
    const scrollContainer = document.querySelector('.characters-scroll');
    if (scrollContainer) {
        scrollContainer.innerHTML += scrollContainer.innerHTML;
    }

    // ===== INITIALIZE EVERYTHING =====
    renderCourses();
    renderPricing('monthly');
    renderTestimonials();

    // Init 3D scenes
    initHeroBackground();
    initHero3D();
    initShowcase3D();
    initFeature3D();

    // Observe reveals
    setTimeout(observeRevealElements, 500);

    // ===== BUTTON EVENTS =====
    document.getElementById('btn-explore')?.addEventListener('click', () => {
        document.getElementById('courses')?.scrollIntoView({ behavior: 'smooth' });
    });

    document.getElementById('btn-view-all')?.addEventListener('click', () => {
        alert('üöÄ Coming soon: Full catalog with 150+ courses for kids aged 2-6!');
    });

    document.getElementById('btn-try-3d')?.addEventListener('click', () => {
        document.getElementById('showcase-3d-container')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });

    document.getElementById('btn-cta-talk')?.addEventListener('click', () => {
        alert('üéÅ Gift subscriptions coming soon! Enter your email to be notified.');
    });
});
D *cascade08DU*cascade08UW *cascade08W]*cascade08]b *cascade08be*cascade08ef *cascade08fr*cascade08rÄ *cascade08ÄÅ*cascade08ÅÇ *cascade08ÇÑ*cascade08Ñ‡ *cascade08‡Í*cascade08Íª *cascade08ªÜ*cascade08Üá *cascade08áç(*cascade08ç(ö( *cascade08ö(πX*cascade08πX¶Y *cascade08¶Y√Y*cascade08√Y§Z *cascade08§ZøZ*cascade08øZ±^ *cascade08±^¿^*cascade08¿^‰^ *cascade08‰^Â^*cascade08Â^ë` *cascade08ë`´f*cascade08´fñh *cascade08ñhóh*cascade08óhÊh *cascade08ÊhÁh*cascade08ÁhÚi *cascade08Úiàj*cascade08àj—l *cascade08—l“l*cascade08“l¬m *cascade08¬m©n*cascade08©np *cascade08pòq*cascade08òqõv *cascade08õv¶v*cascade08¶v˘v *cascade08˘vÑw*cascade08ÑwÖx *cascade08ÖxÜx*cascade08Üxãy *cascade08ãyëy*cascade08ëyÛy *cascade08ÛyÃ}*cascade08Ã}ò~ *cascade08ò~û~*cascade08û~Í~ *cascade08Í~Î~*cascade08Î~· *cascade08·ôè*cascade08ôè⁄è *cascade08⁄è›è*cascade08›è¸í *cascade08¸íÀõ*cascade08Àõ÷û *cascade08÷ûû*cascade08ûÑ§ *cascade08Ñ§ç§*cascade08ç§„§ *cascade08„§Ó§*cascade08Ó§‰• *cascade08‰•Â•*cascade08Â•È• *cascade08È•Í•*cascade08Í•º¶ *cascade08º¶⁄«*cascade08⁄«Æ» *cascade08Æ»±»*cascade08±»–À *cascade08–À¨“*cascade08¨“—’ *cascade08—’Î’*cascade08Î’≈⁄ *cascade08≈⁄»Û*cascade08»Ûª˛ *cascade08ª˛‚˛*cascade08‚˛∏Å *cascade08∏Å√Ç*cascade08√Ç˚É *cascade08˚É®Ñ*cascade08®ÑÌí *cascade08ÌíÔí*cascade08ÔíÆó *cascade08ÆóÃó*cascade08ÃóË• *cascade08Ë•Î•*cascade08Î•ªß *cascade08ªßÃß*cascade08ÃßõÀ *cascade08õÀ”À*cascade08”ÀôÕ *cascade08ôÕ°“*cascade08°“ΩŸ *cascade08ΩŸÿ‹*cascade08ÿ‹†ﬂ *cascade08†ﬂ≠ﬂ*cascade08≠ﬂº· *cascade08º·àÂ*cascade08àÂöÂ *cascade0822file:///c:/Users/novtw/Music/course-website/app.js